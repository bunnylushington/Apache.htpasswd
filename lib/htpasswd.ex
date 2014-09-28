defmodule Apache.Htpasswd do
  
  @sha "{SHA}"
  
  def check(slug, htfile) do
    [user, pass] = String.split slug, ":", parts: 2
    check(user, pass, htfile)
  end

  def check(user, pass, htfile) do
    case get_enc_passwd(user, htfile) do
      nil -> false
      enc -> 
        Enum.any?([:plaintext, :crypt, :sha, :md5], &(match &1, pass, enc))
    end
  end


  def get_enc_passwd(user, htfile) do
    case Enum.find File.stream!(htfile), 
                        &(String.starts_with?(&1, user <> ":")) do
      nil -> nil
      row -> passwd_from_row(row)
    end
  end

  defp passwd_from_row(row) do
    String.strip(row) 
    |> String.split(":", parts: 2) 
    |> List.last
  end

  defp match(:plaintext, pass, enc), do: pass == enc
  defp match(:crypt, pass, enc) do
    <<salt :: binary-size(2), _ :: binary>> = enc
    :crypt.crypt(pass, salt) == enc
  end
  defp match(:md5, pass, enc) do
    {:ok, _, _, _, str} = Apache.PasswdMD5.crypt(pass, enc)
    str == enc
  end
  defp match(:sha, pass, enc) do
    enc == @sha <> Base.encode64(:crypto.hash :sha, pass)
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
