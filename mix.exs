defmodule Htpasswd.Mixfile do
  use Mix.Project

  def project do
    [app: :htpasswd,
     version: "0.0.1",
     elixir: "~> 1.0.0",
     deps: deps]
  end
  def application do
    [applications: [:logger]]
  end

  defp deps do
    [
     {:apache_passwd_md5, "~> 1.0"},
     {:crypt, github: "msantos/crypt"}
    ]
  end
end
