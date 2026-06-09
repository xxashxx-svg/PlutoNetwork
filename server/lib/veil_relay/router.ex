defmodule VeilRelay.Router do
  use Plug.Router

  alias VeilRelay.{Auth, Store}

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
        {"access-control-allow-headers", "content-type, authorization"}
      ])

    if conn.method == "OPTIONS" do
      conn |> send_resp(204, "") |> halt()
    else
      conn
    end
  end

  defp json(conn, status, map) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(map))
  end

  defp authed(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> Store.token_user(token)
      _ -> nil
    end
  end

  # ---- accounts ----
  post "/register" do
    case conn.body_params do
      %{"user" => u, "pass" => p} ->
        case Auth.register(u, p) do
          {:ok, {user, token}} -> json(conn, 201, %{user: user, token: token})
          {:error, msg} -> json(conn, 400, %{error: msg})
        end

      _ ->
        json(conn, 400, %{error: "need user + pass"})
    end
  end

  post "/login" do
    case conn.body_params do
      %{"user" => u, "pass" => p} ->
        case Auth.login(u, p) do
          {:ok, {user, token}} -> json(conn, 200, %{user: user, token: token})
          {:error, msg} -> json(conn, 401, %{error: msg})
        end

      _ ->
        json(conn, 400, %{error: "need user + pass"})
    end
  end

  get "/me" do
    case authed(conn) do
      nil -> json(conn, 401, %{error: "bad token"})
      user -> json(conn, 200, %{user: user})
    end
  end

  # ---- key packages (auth required) ----
  post "/keypackages" do
    with user when not is_nil(user) <- authed(conn),
         %{"key_package" => kp} when is_binary(kp) <- conn.body_params do
      Store.push_key_package(user, kp)
      json(conn, 201, %{ok: true})
    else
      nil -> json(conn, 401, %{error: "sign in first"})
      _ -> json(conn, 400, %{error: "need key_package"})
    end
  end

  get "/keypackages/:user" do
    cond do
      authed(conn) == nil ->
        json(conn, 401, %{error: "sign in first"})

      true ->
        case Store.pop_key_package(user) do
          nil -> json(conn, 404, %{error: "no key packages left"})
          kp -> json(conn, 200, %{key_package: kp})
        end
    end
  end

  # ---- realtime ----
  get "/ws" do
    conn = fetch_query_params(conn)

    case Store.token_user(conn.query_params["token"]) do
      nil ->
        send_resp(conn, 401, "bad token")

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
