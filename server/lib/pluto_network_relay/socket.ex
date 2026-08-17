defmodule PlutoNetworkRelay.Socket do
  # one process per connected client. registers under the user id, then
  # pushes mailbox contents. every frame is durable-first: it lands in the
  # mailbox, gets pushed with a mail id, and is deleted only when the client
  # acks it. a push into a dying connection therefore re-delivers later,
  # and MLS discards duplicate ciphertext, so at-least-once is safe.
  # the relay never looks inside a blob — it can't, it's ciphertext.
  @behaviour WebSock

  alias PlutoNetworkRelay.Store

  @impl true
  def init(%{user: user}) do
    register(user, 5)
    {:push, mail_frames(user), %{user: user}}
  end

  # a half-open twin may be squatting the name; the fresh connection wins
  defp register(user, tries) do
    case Registry.register(PlutoNetworkRelay.Conns, user, nil) do
      {:ok, _} ->
        :ok

      {:error, {:already_registered, stale}} when tries > 0 ->
        send(stale, :replaced)
        Process.sleep(30)
        register(user, tries - 1)

      _ ->
        :ok
    end
  end

  defp mail_frames(user) do
    for {id, frame} <- Store.fetch_mail(user) do
      {:text, frame |> Jason.decode!() |> Map.put("mid", id) |> Jason.encode!()}
    end
  end

  @impl true
  def handle_in({text, [opcode: :text]}, state) do
    case Jason.decode(text) do
      # keepalive: answer so the client can tell a live link from a dead one
      {:ok, %{"ping" => _}} ->
        {:push, {:text, ~s({"pong":1})}, state}

      # receipt: the client has this mail safely, drop it from the mailbox
      {:ok, %{"got" => ids}} when is_list(ids) ->
        Store.ack_mail(state.user, Enum.filter(ids, &is_integer/1))
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

  # a newer connection for this user took over
  @impl true
  def handle_info(:replaced, state), do: {:stop, :normal, state}

  # mail landed for us (local deliver, or Bus heard another instance's pg_notify)
  def handle_info(:check_mail, state) do
    case mail_frames(state.user) do
      [] -> {:ok, state}
      frames -> {:push, frames, state}
    end
  end

  @impl true
  def terminate(_reason, _state), do: :ok

  defp deliver(user, frame) do
    # durable first, always; then wake the local socket if there is one.
    # cross-instance sockets are woken by the Bus via pg_notify.
    Store.stash(user, frame)

    case Registry.lookup(PlutoNetworkRelay.Conns, user) do
      [{pid, _}] -> send(pid, :check_mail)
      [] -> :ok
    end
  end
end
