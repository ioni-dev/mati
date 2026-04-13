defmodule MyApp.HTTPServer do
  def start(port) do
    IO.puts("Starting server on port #{port}")
    :ok
  end
end
