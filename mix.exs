defmodule IP2ProxyErlang.MixProject do
  use Mix.Project

  def project() do
    [
      app: :ip2proxy_erlang,
      version: "3.3.1",
      elixir: "~> 1.0",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      name: "ip2proxy_erlang",
      source_url: "https://github.com/ip2location/ip2proxy-erlang"
    ]
  end

  def application() do
    []
  end

  defp deps() do
    [
      {:ex_doc, "~> 0.14", only: :dev, runtime: false}
    ]
  end

  defp description() do
    "Query where IP address is a VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES), residential proxies (RES), consumer privacy networks (CPN), and enterprise private networks (EPN) by using IP2Proxy database."
  end

  defp package() do
    [
      # This option is only needed when you don't want to use the OTP application name
      name: "ip2proxy_erlang",
      # These are the default files included in the package
      files: ~w(mix.exs README* LICENSE* *.erl),
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ip2location/ip2proxy-erlang"}
    ]
  end
end