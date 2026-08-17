defmodule PlutoNetworkRelay.Store do
  # accounts, key packages and mailboxes live in DETS (plain disk storage,
  # built into OTP) so they survive restarts. everything stored is either
  # public key material, ciphertext, or a password hash — never plaintext.
  # tokens are ETS only: clients just sign in again after a relay restart.
  use GenServer

  def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl true
  def init(_) do
    File.mkdir_p!("data")
    {:ok, _} = :dets.open_file(:users, file: ~c"data/users.dets", type: :set)
    {:ok, _} = :dets.open_file(:key_packages, file: ~c"data/key_packages.dets", type: :bag)
    {:ok, _} = :dets.open_file(:mailboxes, file: ~c"data/mailboxes.dets", type: :duplicate_bag)
    :ets.new(:tokens, [:set, :public, :named_table])
    {:ok, nil}
  end

  # accounts
  def create_user(user, salt, hash) do
    case :dets.insert_new(:users, {user, salt, hash}) do
      true -> :ok
      false -> :taken
    end
  end

  def put_user(user, salt, hash), do: :dets.insert(:users, {user, salt, hash})

  def get_user(user) do
    case :dets.lookup(:users, user) do
      [{^user, salt, hash}] -> {salt, hash}
      [] -> nil
    end
  end

  # tokens (30-day expiry)
  @token_ttl_ms 30 * 24 * 60 * 60 * 1000

  def put_token(token, user),
    do: :ets.insert(:tokens, {token, user, System.system_time(:millisecond) + @token_ttl_ms})

  def token_user(token) when is_binary(token) do
    case :ets.lookup(:tokens, token) do
      [{^token, user, expires}] ->
        if System.system_time(:millisecond) < expires do
          user
        else
          :ets.delete(:tokens, token)
          nil
        end

      [] ->
        nil
    end
  end

  def token_user(_), do: nil

  # key packages: publish many, each fetch pops one (they're one-time use)
  def push_key_package(user, kp), do: :dets.insert(:key_packages, {user, kp})

  # a fresh device starts a new identity — its old key packages are useless
  def clear_key_packages(user), do: :dets.delete(:key_packages, user)

  def pop_key_package(user) do
    case :dets.lookup(:key_packages, user) do
      [] ->
        nil

      [{^user, kp} | _] ->
        :dets.delete_object(:key_packages, {user, kp})
        kp
    end
  end

  # mailbox: ciphertext blobs waiting for an offline user
  def stash(user, blob), do: :dets.insert(:mailboxes, {user, blob})

  def drain(user) do
    blobs = :dets.lookup(:mailboxes, user) |> Enum.map(fn {_, b} -> b end)
    :dets.delete(:mailboxes, user)
    blobs
  end
end
