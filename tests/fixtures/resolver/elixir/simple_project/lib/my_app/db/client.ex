defmodule MyApp.Db.Client do
  defstruct [:dsn]

  def new do
    %__MODULE__{dsn: "localhost:5432"}
  end

  def execute(_client, sql) do
    IO.puts(sql)
  end
end
