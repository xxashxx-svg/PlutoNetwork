defmodule PlutoNetworkRelay.Bus do
  # cross-instance delivery (Postgres mode). hosts run overlapping instances
  # during deploys, and each instance only knows its own sockets. stash/2
  # fires pg_notify, every instance hears it, and whichever one holds the
  # recipient's socket drains their mailbox immediately.
  use GenServer

  def start_link(url), do: GenServer.start_link(__MODULE__, url, name: __MODULE__)

  @impl true
  def init(url) do
    opts =
      PlutoNetworkRelay.Store.Pg.conn_opts(url)
      |> Keyword.drop([:name, :pool_size])
      |> Keyword.put(:auto_reconnect, true)

    {:ok, notif} = Postgrex.Notifications.start_link(opts)
    Postgrex.Notifications.listen(notif, "pluto_mail")
    {:ok, notif}
  end

  @impl true
  def handle_info({:notification, _, _, "pluto_mail", user}, state) do
    case Registry.lookup(PlutoNetworkRelay.Conns, user) do
      [{pid, _}] -> send(pid, :check_mail)
      [] -> :ok
    end

    {:noreply, state}
  end

  def handle_info(_, state), do: {:noreply, state}
end
