defmodule PlutoNetworkRelay.Router do
  use Plug.Router

  alias PlutoNetworkRelay.{Auth, Store}

  plug :cors
  # in production the web client ships inside the image at ./static
  plug Plug.Static, at: "/", from: "static"
  plug :match
  # pass: raw bodies (blobs/vault ciphertext) flow through untouched
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason, pass: ["*/*"]
  plug :dispatch

  # browser clients live on a different origin than the relay
  defp cors(conn, _opts) do
    conn =
      merge_resp_headers(conn, [
        {"access-control-allow-origin", "*"},
        {"access-control-allow-methods", "GET, POST, PUT, OPTIONS"},
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

  # old + new are derived auth keys, never real passwords — same as login
  post "/password" do
    with user when not is_nil(user) <- authed(conn),
         %{"old" => old, "new" => new} when is_binary(old) and is_binary(new) <- conn.body_params do
      case Auth.change_password(user, old, new) do
        :ok -> json(conn, 200, %{ok: true})
        {:error, msg} -> json(conn, 401, %{error: msg})
      end
    else
      nil -> json(conn, 401, %{error: "sign in first"})
      _ -> json(conn, 400, %{error: "need old + new"})
    end
  end

  get "/me" do
    case authed(conn) do
      nil -> json(conn, 401, %{error: "bad token"})
      user -> json(conn, 200, %{user: user})
    end
  end

  # exact-match existence check for the search bar. deliberately not a
  # search: you can only confirm a name you already know, never list users
  get "/users/:name" do
    cond do
      authed(conn) == nil -> json(conn, 401, %{error: "sign in first"})
      Store.get_user(name) != nil -> json(conn, 200, %{ok: true})
      true -> json(conn, 404, %{error: "no such user"})
    end
  end

  # ---- key packages (auth required) ----
  post "/keypackages" do
    with user when not is_nil(user) <- authed(conn),
         %{"key_package" => kp} when is_binary(kp) <- conn.body_params do
      if conn.body_params["reset"] == true, do: Store.clear_key_packages(user)
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

  # ---- encrypted media blobs (auth required, content is client-side ciphertext) ----
  # ids are 128-bit random so they're unguessable; the payload is opaque to us anyway
  @blob_id ~r/^[A-Za-z0-9_-]{16,}$/

  post "/blobs" do
    with user when not is_nil(user) <- authed(conn),
         {:ok, body, conn} when byte_size(body) > 0 <- read_all(conn) do
      _ = user
      id = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      Store.put_blob(id, body)
      json(conn, 201, %{id: id})
    else
      nil -> json(conn, 401, %{error: "sign in first"})
      {:error, :too_big} -> json(conn, 413, %{error: "blob too big (#{max_blob_mb()}MB max)"})
      _ -> json(conn, 400, %{error: "empty body"})
    end
  end

  get "/blobs/:id" do
    cond do
      authed(conn) == nil ->
        json(conn, 401, %{error: "sign in first"})

      not Regex.match?(@blob_id, id) ->
        json(conn, 400, %{error: "bad id"})

      true ->
        case Store.get_blob(id) do
          nil -> json(conn, 404, %{error: "no such blob"})
          bytes -> conn |> put_resp_content_type("application/octet-stream") |> send_resp(200, bytes)
        end
    end
  end

  # ---- history vault (client-side encrypted backup, one per user) ----
  put "/vault" do
    with user when not is_nil(user) <- authed(conn),
         {:ok, body, conn} when byte_size(body) > 0 <- read_all(conn) do
      Store.put_vault(user, body)
      json(conn, 200, %{ok: true})
    else
      nil -> json(conn, 401, %{error: "sign in first"})
      {:error, :too_big} -> json(conn, 413, %{error: "vault too big"})
      _ -> json(conn, 400, %{error: "empty body"})
    end
  end

  get "/vault" do
    case authed(conn) do
      nil ->
        json(conn, 401, %{error: "sign in first"})

      user ->
        case Store.get_vault(user) do
          nil -> json(conn, 404, %{error: "no vault yet"})
          bytes -> conn |> put_resp_content_type("application/octet-stream") |> send_resp(200, bytes)
        end
    end
  end

  # free-tier databases are small; MAX_BLOB_MB caps per-file size (default 64)
  defp max_blob_mb, do: String.to_integer(System.get_env("MAX_BLOB_MB") || "64")

  defp read_all(conn, acc \\ [], size \\ 0) do
    case Plug.Conn.read_body(conn, length: 8_000_000) do
      {:ok, data, conn} -> {:ok, IO.iodata_to_binary([acc, data]), conn}
      {:more, data, conn} ->
        size = size + byte_size(data)
        if size > max_blob_mb() * 1024 * 1024, do: {:error, :too_big}, else: read_all(conn, [acc, data], size)
      {:error, _} = err -> err
    end
  end

  # ---- realtime ----
  get "/ws" do
    conn = fetch_query_params(conn)

    case Store.token_user(conn.query_params["token"]) do
      nil ->
        send_resp(conn, 401, "bad token")

      user ->
        WebSockAdapter.upgrade(conn, PlutoNetworkRelay.Socket, %{user: user}, timeout: 300_000)
    end
  end

  get "/health" do
    send_resp(conn, 200, "ok")
  end

  get "/" do
    if File.exists?("static/index.html") do
      conn |> put_resp_content_type("text/html") |> send_file(200, "static/index.html")
    else
      send_resp(conn, 200, "PlutoNetwork relay")
    end
  end

  match _ do
    send_resp(conn, 404, "nope")
  end
end
