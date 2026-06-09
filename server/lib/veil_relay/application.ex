defmodule VeilRelay.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: VeilRelay.Conns},
      VeilRelay.Store,
      {Bandit, plug: VeilRelay.Router, port: port()}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: VeilRelay.Supervisor)
  end

  defp port, do: String.to_integer(System.get_env("PORT") || "4000")
end
