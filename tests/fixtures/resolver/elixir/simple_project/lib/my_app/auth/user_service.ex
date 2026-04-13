defmodule MyApp.Auth.UserService do
  alias MyApp.Db.Client

  def create_user(name, client) do
    Client.execute(client, "INSERT INTO users (name) VALUES ('#{name}')")
  end
end
