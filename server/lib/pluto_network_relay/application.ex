defmodule PlutoNetworkRelay.Application do
  use Application

  alias PlutoNetworkRelay.Store

  @impl true
  def start(_type, _args) do
    storage =
      case System.get_env("DATABASE_URL") do
        nil ->
          :persistent_term.put(:pluto_store_backend, Store.Dets)
          [Store.Dets]

        url ->
          :persistent_term.put(:pluto_store_backend, Store.Pg)

          [
            Store.Pg.child_spec(url),
            %{id: :migrations, start: {Store.Pg, :start_migrations, [nil]}}
          ]
      end

    children =
      [{Registry, keys: :unique, name: PlutoNetworkRelay.Conns}] ++
        storage ++
        [{Bandit, plug: PlutoNetworkRelay.Router, port: port()}]

    Supervisor.start_link(children, strategy: :one_for_one, name: PlutoNetworkRelay.Supervisor)
  end

  defp port, do: String.to_integer(System.get_env("PORT") || "4000")
end
