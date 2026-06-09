defmodule VeilRelay.Auth do
  # accounts + tokens. passwords are pbkdf2-sha256 (100k rounds, per-user salt)
  # via OTP's :crypto — no native deps to compile.
  alias VeilRelay.Store

  @name_re ~r/^[a-z0-9_]{2,24}$/

  def register(user, pass) when is_binary(user) and is_binary(pass) do
    cond do
      not Regex.match?(@name_re, user) ->
        {:error, "name must be 2-24 chars: a-z, 0-9, _"}

      byte_size(pass) < 6 ->
        {:error, "password needs at least 6 characters"}

      true ->
        salt = :crypto.strong_rand_bytes(16)

        case Store.create_user(user, salt, hash(pass, salt)) do
          :ok -> {:ok, issue(user)}
          :taken -> {:error, "that name is taken"}
        end
    end
  end

  def register(_, _), do: {:error, "bad request"}

  def login(user, pass) when is_binary(user) and is_binary(pass) do
    case Store.get_user(user) do
      nil ->
        {:error, "no account with that name"}

      {salt, stored} ->
        if :crypto.hash_equals(hash(pass, salt), stored) do
          {:ok, issue(user)}
        else
          {:error, "wrong password"}
        end
    end
  end

  def login(_, _), do: {:error, "bad request"}

  defp issue(user) do
    token = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
    Store.put_token(token, user)
    {user, token}
  end

  defp hash(pass, salt), do: :crypto.pbkdf2_hmac(:sha256, pass, salt, 100_000, 32)
end
