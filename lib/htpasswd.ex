defmodule Apache.Htpasswd do
  
  @sha "{SHA}"
  @atoz 'abcdefghijklmnopqrstuvwxyz'
  
  @moduledoc """ 
  Provides basic htpasswd(1) functions as a library.  The hashing
  methods available are :md5 (the default), :sha, :crypt, and
  :plaintext.

  # Examples
  iex> Apache.Htpasswd.check "user:pass", "test/htfile"
  false

  iex> Apache.Htpasswd.check "plaintext:plaintext", "test/htfile"
  true

  iex> Apache.Htpasswd.encode! "user", "pass"
  "user:$apr1$O5f9TZT.$IBzxX8byvgfsLYp/dkIzC/"

  iex> Apache.Htpasswd.encode! "user", "pass", :sha
  "user:{SHA}nU4eI71bcnBGqeO0t9tXvY1u5oQ="

  iex> Apache.Htpasswd.check "user:pass", Apache.Htpasswd.encode("user", "pass")
  true  

  iex> Apache.Htpasswd.add("user", "pass", "/tmp/htpasswd")
  {:ok, "user:$apr1$on6He14N$3AeecTsC32uTadbYK1Ij4/"}

  iex> Apache.Htpasswd.rm("user", "/tmp/htpasswd")
  :ok
  """

  require Logger

  def check(nil, _), do: false
  def check(slug, htfile_or_string) do
    [user, plaintext] = String.split slug, ":", parts: 2
    if File.exists?(htfile_or_string) do
      check_against_file(user, plaintext, htfile_or_string)
    else
      check_against_string(user, plaintext, htfile_or_string)
    end
  end

  def encode(user, plaintext, method \\ :md5) do
    case hash(method, plaintext) do
      {:ok, encrypted} -> {:ok, Enum.join([user, encrypted], ":")}
      {:error, err} -> {:error, err}
    end
  end
  
  def encode!(user, plaintext, method \\ :md5) do
    case encode(user, plaintext, method) do
      {:ok, string} -> string
      {:error, err} -> raise RuntimeError, message: err
    end
  end

  def add(user, plaintext, file, method \\ :md5) do
    if (File.exists?(file)), do: rm(user, file)
    string = encode!(user, plaintext, method)
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
    Enum.any?([:plaintext, :sha, :md5, :crypt], 
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
    if Regex.match?(~r/:/, string) do
      String.strip(string) 
      |> String.split(":", parts: 2) 
      |> List.last
    else
      nil
    end
  end

  defp match(:plaintext, plaintext, encrypted), do: plaintext == encrypted
  defp match(:crypt, plaintext, encrypted) do
    if Code.ensure_loaded?(:crypt) do
      <<salt :: binary-size(2), _ :: binary>> = encrypted
      :crypt.crypt(plaintext, salt) == encrypted
    else
      Logger.debug(crypt_unavailable)
      false
    end
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
    {:ok, str}
  end
  defp hash(:sha, plaintext) do 
    {:ok, @sha <> Base.encode64(:crypto.hash :sha, plaintext)}
  end
  defp hash(:plaintext, plaintext), do: {:ok, plaintext}
  defp hash(:crypt, plaintext) do
    if Code.ensure_loaded?(:crypt) do
      {:ok, :crypt.crypt(plaintext, salt(2))}
    else 
      Logger.error("Crypt dependency unavailable, hashing failed.")
      {:error, "crypt dependency not found, :crypt method unavailable"}
    end
  end
  defp hash(method, _) do 
    Logger.error("Unknown encoding method :#{ method }")
    {:error, "invalid encoding method :#{ method }"}
  end

  defp salt(length, seed \\ :os.timestamp) do
    :random.seed(seed)
    Enum.shuffle(@atoz) |> Enum.take(length) |> List.to_string
  end

  defp crypt_unavailable do
    """
    The dependency Crypt is unavailable.  Checking and encoding passwords
    with the crypt schema is impossible.
    """
  end
  
end
