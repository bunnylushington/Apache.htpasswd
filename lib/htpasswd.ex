defmodule Apache.Htpasswd do
  
  @sha "{SHA}"
  @atoz 'abcdefghijklmnopqrstuvwxyz'
  
  def check(slug, htfile_or_string) do
    [user, plaintext] = String.split slug, ":", parts: 2
    case File.exists?(htfile_or_string) do
      true ->  check_against_file(user, plaintext, htfile_or_string)
      false -> check_against_string(user, plaintext, htfile_or_string)
    end
  end

  def encode(user, plaintext, method \\ :md5) do
    Enum.join [user, hash(method, plaintext)], ":"
  end

  def add(user, plaintext, file, method \\ :md5) do
    if (File.exists?(file)), do: rm(user, file)
    string = encode(user, plaintext, method)
    case File.open(file, [:append]) do
      {:ok, device} -> IO.puts(device, string)
                       File.close(device)
                       {:ok, string}
      {:error, reason} -> {:error, reason}
    end
  end

  def rm(user, file) do
    File.write!(file, filtered_file_contents(user, file))
  end

  def filtered_file_contents(user, file) do
    File.stream!(file) |> Enum.filter &(! String.starts_with?(&1, user <> ":"))
  end

  def check_against_file(user, plaintext, htfile) do
    case password_from_file(user, htfile) do
      nil -> false
      encrypted -> validate_password(encrypted, plaintext)
    end
  end

  def check_against_string(user, plaintext, string) do
    case String.starts_with?(string, user) do
      false -> false
      true -> 
        case password_from_string(string) do
          nil -> false
          encrypted -> validate_password(encrypted, plaintext)
        end
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

  defp hash(:md5, plaintext) do
    {:ok, _, _, _, str} = Apache.PasswdMD5.crypt(plaintext)
    str
  end
  defp hash(:sha, plaintext) do 
    @sha <> Base.encode64(:crypto.hash :sha, plaintext)
  end
  defp hash(:plaintext, plaintext), do: plaintext
  defp hash(:crypt, plaintext), do: :crypt.crypt(plaintext, salt(2))
  defp hash(method, _) do 
    raise(RuntimeError, message: "invalid encoding method :#{ method }")
  end

  defp salt(length, seed \\ :os.timestamp) do
    :random.seed(seed)
    Enum.shuffle(@atoz) |> Enum.take(length) |> List.to_string
  end

end
