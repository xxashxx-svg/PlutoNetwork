defmodule PlutoNetworkRelay.Store.Pg do
  # stateless backend: everything in Postgres (Neon, Supabase, Koyeb, any
  # DATABASE_URL). TLS is verified against the system CA store.

  @conn __MODULE__.Conn

  def child_spec(url) do
    %{id: @conn, start: {Postgrex, :start_link, [conn_opts(url)]}}
  end

  def conn_opts(url) do
    uri = URI.parse(url)

    {user, pass} =
      case String.split(uri.userinfo || "", ":", parts: 2) do
        [u, p] -> {u, p}
        [u] -> {u, nil}
      end

    ssl? = (URI.decode_query(uri.query || "") |> Map.get("sslmode", "require")) != "disable"

    opts = [
      name: @conn,
      hostname: uri.host,
      port: uri.port || 5432,
      username: URI.decode(user),
      database: String.trim_leading(uri.path || "/postgres", "/"),
      pool_size: 3
    ]

    opts = if pass, do: opts ++ [password: URI.decode(pass)], else: opts

    if ssl? do
      opts ++
        [
          ssl: [
            verify: :verify_peer,
            cacerts: :public_key.cacerts_get(),
            server_name_indication: String.to_charlist(uri.host),
            customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
          ]
        ]
    else
      opts
    end
  end

  @schema [
    "CREATE TABLE IF NOT EXISTS users (name text PRIMARY KEY, salt bytea NOT NULL, hash bytea NOT NULL)",
    "CREATE TABLE IF NOT EXISTS tokens (token text PRIMARY KEY, name text NOT NULL, expires_at bigint NOT NULL)",
    "CREATE TABLE IF NOT EXISTS key_packages (id bigserial PRIMARY KEY, name text NOT NULL, kp text NOT NULL)",
    "CREATE INDEX IF NOT EXISTS kp_name ON key_packages (name)",
    "CREATE TABLE IF NOT EXISTS mailboxes (id bigserial PRIMARY KEY, name text NOT NULL, frame text NOT NULL)",
    "CREATE INDEX IF NOT EXISTS mb_name ON mailboxes (name)",
    "CREATE TABLE IF NOT EXISTS blobs (id text PRIMARY KEY, data bytea NOT NULL, inserted_at timestamptz NOT NULL DEFAULT now())",
    "CREATE TABLE IF NOT EXISTS vaults (name text PRIMARY KEY, data bytea NOT NULL)"
  ]

  # runs as a supervised child right after the pool: migrate, sweep, then :ignore
  def start_migrations(_) do
    Enum.each(@schema, &q!/1)
    q!("DELETE FROM tokens WHERE expires_at < $1", [System.system_time(:millisecond)])

    # free databases are small; BLOB_TTL_DAYS trades old media for space.
    # restarts are frequent on free hosts, so boot-time is periodic enough.
    case System.get_env("BLOB_TTL_DAYS") do
      nil -> :ok
      days -> q!("DELETE FROM blobs WHERE inserted_at < now() - ($1 || ' days')::interval", [days])
    end

    :ignore
  end

  defp q!(sql, params \\ []), do: Postgrex.query!(@conn, sql, params)

  def create_user(user, salt, hash) do
    case Postgrex.query(@conn, "INSERT INTO users (name, salt, hash) VALUES ($1, $2, $3)", [user, salt, hash]) do
      {:ok, _} -> :ok
      {:error, %{postgres: %{code: :unique_violation}}} -> :taken
    end
  end

  def put_user(user, salt, hash) do
    q!("UPDATE users SET salt = $2, hash = $3 WHERE name = $1", [user, salt, hash])
    :ok
  end

  def get_user(user) do
    case q!("SELECT salt, hash FROM users WHERE name = $1", [user]).rows do
      [[salt, hash]] -> {salt, hash}
      [] -> nil
    end
  end

  def put_token(token, user, expires),
    do: q!("INSERT INTO tokens (token, name, expires_at) VALUES ($1, $2, $3)", [token, user, expires])

  def token_user(token, now) do
    case q!("SELECT name FROM tokens WHERE token = $1 AND expires_at > $2", [token, now]).rows do
      [[user]] -> user
      [] -> nil
    end
  end

  def push_key_package(user, kp),
    do: q!("INSERT INTO key_packages (name, kp) VALUES ($1, $2)", [user, kp])

  def clear_key_packages(user), do: q!("DELETE FROM key_packages WHERE name = $1", [user])

  def pop_key_package(user) do
    sql = """
    DELETE FROM key_packages
    WHERE id = (SELECT id FROM key_packages WHERE name = $1 ORDER BY id LIMIT 1)
    RETURNING kp
    """

    case q!(sql, [user]).rows do
      [[kp]] -> kp
      [] -> nil
    end
  end

  def stash(user, frame), do: q!("INSERT INTO mailboxes (name, frame) VALUES ($1, $2)", [user, frame])

  def drain(user) do
    rows = q!("SELECT id, frame FROM mailboxes WHERE name = $1 ORDER BY id", [user]).rows
    ids = Enum.map(rows, fn [id, _] -> id end)
    if ids != [], do: q!("DELETE FROM mailboxes WHERE id = ANY($1)", [ids])
    Enum.map(rows, fn [_, frame] -> frame end)
  end

  def put_blob(id, bytes), do: q!("INSERT INTO blobs (id, data) VALUES ($1, $2)", [id, bytes])

  def get_blob(id) do
    case q!("SELECT data FROM blobs WHERE id = $1", [id]).rows do
      [[bytes]] -> bytes
      [] -> nil
    end
  end

  def put_vault(user, bytes) do
    q!(
      "INSERT INTO vaults (name, data) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET data = $2",
      [user, bytes]
    )
  end

  def get_vault(user) do
    case q!("SELECT data FROM vaults WHERE name = $1", [user]).rows do
      [[bytes]] -> bytes
      [] -> nil
    end
  end
end
