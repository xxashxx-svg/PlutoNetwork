defmodule PlutoNetworkRelay.Store.Dets do
  # self-host backend: DETS tables + plain files under data/
  use GenServer

  def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl true
  def init(_) do
    File.mkdir_p!("data/blobs")
    File.mkdir_p!("data/vaults")
    {:ok, _} = :dets.open_file(:users, file: ~c"data/users.dets", type: :set)
    {:ok, _} = :dets.open_file(:tokens, file: ~c"data/tokens.dets", type: :set)
    {:ok, _} = :dets.open_file(:key_packages, file: ~c"data/key_packages.dets", type: :bag)
    {:ok, _} = :dets.open_file(:mailboxes, file: ~c"data/mailboxes.dets", type: :duplicate_bag)
    {:ok, nil}
  end

  def create_user(user, salt, hash) do
    case :dets.insert_new(:users, {user, salt, hash}) do
      true -> :ok
      false -> :taken
    end
  end

  def put_user(user, salt, hash) do
    :dets.insert(:users, {user, salt, hash})
    :ok
  end

  def get_user(user) do
    case :dets.lookup(:users, user) do
      [{^user, salt, hash}] -> {salt, hash}
      [] -> nil
    end
  end

  def put_token(token, user, expires), do: :dets.insert(:tokens, {token, user, expires})

  def token_user(token, now) do
    case :dets.lookup(:tokens, token) do
      [{^token, user, expires}] when now < expires ->
        user

      [{^token, _, _}] ->
        :dets.delete(:tokens, token)
        nil

      [] ->
        nil
    end
  end

  def push_key_package(user, kp), do: :dets.insert(:key_packages, {user, kp})
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

  def stash(user, frame),
    do: :dets.insert(:mailboxes, {user, {:erlang.unique_integer([:monotonic, :positive]), frame}})

  def fetch_mail(user) do
    :dets.lookup(:mailboxes, user)
    |> Enum.flat_map(fn
      {_, {id, frame}} when is_integer(id) ->
        [{id, frame}]

      {^user, frame} = legacy when is_binary(frame) ->
        # pre-ack row: deliver once, the old drain way
        :dets.delete_object(:mailboxes, legacy)
        [{0, frame}]
    end)
    |> Enum.sort()
    |> Enum.take(500)
  end

  def ack_mail(user, ids) do
    for {^user, {id, _}} = obj <- :dets.lookup(:mailboxes, user), id in ids do
      :dets.delete_object(:mailboxes, obj)
    end

    :ok
  end

  def put_blob(id, bytes), do: File.write!("data/blobs/#{id}", bytes)

  def get_blob(id) do
    case File.read("data/blobs/#{id}") do
      {:ok, bytes} -> bytes
      _ -> nil
    end
  end

  def put_vault(user, bytes), do: File.write!("data/vaults/#{user}.bin", bytes)

  def get_vault(user) do
    case File.read("data/vaults/#{user}.bin") do
      {:ok, bytes} -> bytes
      _ -> nil
    end
  end
end
