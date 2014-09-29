defmodule Apache.Htpasswd do
  
  @sha "{SHA}"
  
  def check(slug, htfile_or_string) do
    [user, plaintext] = String.split slug, ":", parts: 2
    case File.exists?(htfile_or_string) do
      true ->  check_against_file(user, plaintext, htfile_or_string)
      false -> check_against_string(user, plaintext, htfile_or_string)
    end
  end

  def check_against_file(user, plaintext, htfile) do
    case password_from_file(user, htfile) do
      nil -> false
      encrypted -> validate_password(encrypted, plaintext)
    end
  end

  def check_against_string(user, plaintext, string) do
    case password_from_string(string) do
      nil -> false
      encrypted -> validate_password(encrypted, plaintext)
    end
  end

  defp validate_password(encrypted, plaintext) do
    Enum.any?([:plaintext, :crypt, :sha, :md5], 
              &(match &1, plaintext, encrypted))
  end

  defp password_from_file(user, htfile) do
    case Enum.find File.stream!(htfile), 
                        &(String.starts_with?(&1, user <> ":")) do
      nil -> nil
      row -> password_from_string(row)
    end
  end
  
  defp password_from_string(string) do
    case Regex.match?(~r/:/, string) do
      true -> String.strip(string) 
              |> String.split(":", parts: 2) 
              |> List.last
      false -> nil
    end
  end

  defp match(:plaintext, plaintext, encrypted), do: plaintext == encrypted
  defp match(:crypt, plaintext, encrypted) do
    <<salt :: binary-size(2), _ :: binary>> = encrypted
    :crypt.crypt(plaintext, salt) == encrypted
  end
  defp match(:md5, plaintext, encrypted) do
    {:ok, _, _, _, str} = Apache.PasswdMD5.crypt(plaintext, encrypted)
    str == encrypted
  end
  defp match(:sha, plaintext, encrypted) do
    encrypted == @sha <> Base.encode64(:crypto.hash :sha, plaintext)
  end

  # -------------------------------------------------- ENCODING.  
  
  def encode(user, pass, method \\ :md5) do
    Enum.join [user, do_hash(method, pass)], ":"
  end
              
  defp do_hash(:md5, pass) do
     {:ok, _, _, _, str} = Apache.PasswdMD5.crypt(pass)
     str
  end
  defp do_hash(:sha, pass), do: @sha <> Base.encode64(:crypto.hash :sha, pass)
  defp do_hash(:plaintext, pass), do: pass
  defp do_hash(:crypt, pass), do: :crypt.crypt(pass, "ab")
  defp do_hash(m, _), do: raise(RuntimeError, 
                               message: "invalid hash algo :#{ m }")



end
