defmodule VeilRelay.Router do
  use Plug.Router

  plug :cors
  plug :match
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  plug :dispatch

  # browser clients live on a different origin than the relay
  defp cors(conn, _opts) do
    conn =
      merge_resp_headers(conn, [
        {"access-control-allow-origin", "*"},
        {"access-control-allow-methods", "GET, POST, OPTIONS"},
        {"access-control-allow-headers", "content-type"}
      ])

    if conn.method == "OPTIONS" do
      conn |> send_resp(204, "") |> halt()
    else
      conn
    end
  end

  # clients publish key packages so others can invite them
  post "/keypackages" do
    case conn.body_params do
      %{"user" => user, "key_package" => kp} when is_binary(user) and is_binary(kp) ->
        VeilRelay.Store.push_key_package(user, kp)
        send_resp(conn, 201, "ok")

      _ ->
        send_resp(conn, 400, ~s({"error":"need user + key_package"}))
    end
  end

  # fetch (and consume) one key package for a user
  get "/keypackages/:user" do
    case VeilRelay.Store.pop_key_package(user) do
      nil -> send_resp(conn, 404, ~s({"error":"no key packages left"}))
      kp -> send_resp(conn, 200, Jason.encode!(%{key_package: kp}))
    end
  end

  get "/ws" do
    conn = fetch_query_params(conn)

    case conn.query_params["user"] do
      nil ->
        send_resp(conn, 400, "need ?user=")

      user ->
        WebSockAdapter.upgrade(conn, VeilRelay.Socket, %{user: user}, timeout: 300_000)
    end
  end

  get "/health" do
    send_resp(conn, 200, "ok")
  end

  match _ do
    send_resp(conn, 404, "nope")
  end
end
