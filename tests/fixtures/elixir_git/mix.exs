defmodule MyApp.MixProject do
  use Mix.Project

  defp deps do
    [
      {:stellar_sdk, github: "kommitters/stellar_sdk"}
    ]
  end
end
