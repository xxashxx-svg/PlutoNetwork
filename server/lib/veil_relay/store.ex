defmodule VeilRelay.Store do
  # ETS for v1 — everything here is public key material or ciphertext,
  # so losing it on restart is annoying but never a confidentiality problem.
  # swap for postgres when persistence matters.
  use GenServer

  def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl true
  def init(_) do
    :ets.new(:key_packages, [:bag, :public, :named_table])
    :ets.new(:mailboxes, [:duplicate_bag, :public, :named_table])
    {:ok, nil}
  end

  # key packages: publish many, each fetch pops one (they're one-time use)
  def push_key_package(user, kp), do: :ets.insert(:key_packages, {user, kp})

  def pop_key_package(user) do
    case :ets.lookup(:key_packages, user) do
      [] ->
        nil

      [{^user, kp} | _] ->
        :ets.delete_object(:key_packages, {user, kp})
        kp
    end
  end

  # mailbox: ciphertext blobs waiting for an offline user
  def stash(user, blob), do: :ets.insert(:mailboxes, {user, blob})

  def drain(user) do
    blobs = :ets.lookup(:mailboxes, user) |> Enum.map(fn {_, b} -> b end)
    :ets.delete(:mailboxes, user)
    blobs
  end
end
