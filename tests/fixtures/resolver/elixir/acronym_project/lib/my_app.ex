defmodule MyApp do
  alias MyApp.HTTPServer
  alias MyApp.XMLParser

  def start do
    server = HTTPServer.start(8080)
    XMLParser.parse("<root/>")
  end
end
