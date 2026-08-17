defmodule PlutoNetworkRelay.Socket do
  # one process per connected client. registers under the user id,
  # drains their mailbox on connect, then just routes opaque blobs.
  # the relay never looks inside a blob — it can't, it's ciphertext.
  @behaviour WebSock

  @impl true
  def init(%{user: user}) do
    Registry.register(PlutoNetworkRelay.Conns, user, nil)
    queued = PlutoNetworkRelay.Store.drain(user) |> Enum.map(&{:text, &1})
    {:push, queued, %{user: user}}
  end

  @impl true
  def handle_in({text, [opcode: :text]}, state) do
    case Jason.decode(text) do
      # keepalive — any frame resets the idle timer
      {:ok, %{"ping" => _}} ->
        {:ok, state}

      # sender knows the roster (MLS clients track membership) and
      # addresses recipients explicitly. blob = base64 ciphertext.
      # kind is client-side routing ("welcome" vs "msg") — opaque to us
      {:ok, %{"to" => recipients, "blob" => blob} = payload}
      when is_list(recipients) and is_binary(blob) ->
        frame =
          Jason.encode!(%{
            from: state.user,
            blob: blob,
            kind: Map.get(payload, "kind", "msg")
          })

        Enum.each(recipients, &deliver(&1, frame))
        {:ok, state}

      _ ->
        {:push, {:text, ~s({"error":"bad frame"})}, state}
    end
  end

  @impl true
  def handle_info({:deliver, frame}, state) do
    {:push, {:text, frame}, state}
  end

  # another instance stashed mail for us (Bus heard the pg_notify)
  def handle_info(:check_mail, state) do
    case PlutoNetworkRelay.Store.drain(state.user) do
      [] -> {:ok, state}
      frames -> {:push, Enum.map(frames, &{:text, &1}), state}
    end
  end

  @impl true
  def terminate(_reason, _state), do: :ok

  defp deliver(user, frame) do
    case Registry.lookup(PlutoNetworkRelay.Conns, user) do
      [{pid, _}] -> send(pid, {:deliver, frame})
      [] -> PlutoNetworkRelay.Store.stash(user, frame)
    end
  end
end
