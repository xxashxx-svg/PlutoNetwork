defmodule PlutoNetworkRelay.Store do
  # one storage API, two backends. DATABASE_URL set -> Postgres, which makes
  # the container fully stateless (free hosts can wipe or sleep it, nothing
  # is lost). No DATABASE_URL -> DETS + local disk for simple self-hosting.
  # everything stored is public key material, ciphertext, or a password hash.

  @token_ttl_ms 30 * 24 * 60 * 60 * 1000

  defp backend, do: :persistent_term.get(:pluto_store_backend)

  # accounts
  def create_user(user, salt, hash), do: backend().create_user(user, salt, hash)
  def put_user(user, salt, hash), do: backend().put_user(user, salt, hash)
  def get_user(user), do: backend().get_user(user)

  # tokens (30-day expiry, survive restarts so naps don't log everyone out)
  def put_token(token, user),
    do: backend().put_token(token, user, System.system_time(:millisecond) + @token_ttl_ms)

  def token_user(token) when is_binary(token),
    do: backend().token_user(token, System.system_time(:millisecond))

  def token_user(_), do: nil

  # key packages: publish many, each fetch pops one (they're one-time use)
  def push_key_package(user, kp), do: backend().push_key_package(user, kp)
  def clear_key_packages(user), do: backend().clear_key_packages(user)
  def pop_key_package(user), do: backend().pop_key_package(user)

  # mailbox: every frame lands here first and is deleted only after the
  # recipient's client confirms receipt (at-least-once delivery; MLS drops
  # any duplicate ciphertext, so redelivery is always safe)
  def stash(user, frame), do: backend().stash(user, frame)
  def fetch_mail(user), do: backend().fetch_mail(user)
  def ack_mail(user, ids), do: backend().ack_mail(user, ids)

  # encrypted media blobs + history vaults
  def put_blob(id, bytes), do: backend().put_blob(id, bytes)
  def get_blob(id), do: backend().get_blob(id)
  def put_vault(user, bytes), do: backend().put_vault(user, bytes)
  def get_vault(user), do: backend().get_vault(user)
end
