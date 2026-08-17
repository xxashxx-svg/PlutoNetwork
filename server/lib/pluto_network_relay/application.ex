defmodule PlutoNetworkRelay.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: PlutoNetworkRelay.Conns},
      PlutoNetworkRelay.Store,
      {Bandit, plug: PlutoNetworkRelay.Router, port: port()}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: PlutoNetworkRelay.Supervisor)
  end

  defp port, do: String.to_integer(System.get_env("PORT") || "4000")
end
