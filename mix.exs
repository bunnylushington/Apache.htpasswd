defmodule Htpasswd.Mixfile do
  use Mix.Project

  def project do
    [app: :htpasswd,
     version: "1.0.2",
     elixir: "~> 1.0.0",
     description: description,
     package: package,
     deps: deps]
  end

  def application do
    [applications: [:logger]]
  end
  
  def description do 
    """ 
    Provides basic htpasswd(1) functions as a library: encode and
    check passwords in MD5, SHA, crypt, or plaintext format, add to
    and delete from htaccess files.
    """
  end

  def package do
    [
     files: ["lib", "mix.exs", "README*", "test"],
     contributors: ["Kevin Montuori"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/kevinmontuori/Apache.htpasswd"}
    ]
  end

  defp deps do
    [
     {:apache_passwd_md5, "~> 1.0"},
     {:crypt, github: "msantos/crypt"}
    ]
  end
end
