defmodule MyApp do
  alias MyApp.Auth.UserService
  alias MyApp.Db.Client

  def start do
    client = Client.new()
    UserService.create_user("admin", client)
  end
end
