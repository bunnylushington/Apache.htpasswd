defmodule Htpasswd do

  @MD5_magic "$apr1$"

  def check(slug, htfile) do
    [user, pass] = String.split slug, ":", parts: 2
    check(user, pass, htfile)
  end

  def check(user, pass, htfile) do
    enc = get_enc_passwd(user, htfile)
    cond do
      match :plaintext, pass, enc -> true
      match :crypt, pass, enc -> true
      match :md5, pass, enc -> true
      true -> false
    end
  end

  def get_enc_passwd(user, htfile) do
    case Enum.find File.stream!(htfile), 
                        &(String.starts_with?(&1, user <> ":")) do
      nil -> nil
      row ->  String.strip(row) 
              |> String.split(":", parts: 2) 
              |> List.last
    end
  end

  def match(:plaintext, pass, enc), do: pass == enc
  def match(:crypt, pass, enc) do
    <<salt :: binary-size(2), _ :: binary>> = enc
    :crypt.crypt(pass, salt) == enc
  end
  def match(:md5, pass, enc) do
    case String.starts_with?(enc, @MD5_magic) do
      true -> [_, salt, hash] = String.split enc, "$", trim: true, parts: 3
      false -> false
    end
    
  end
  
end
