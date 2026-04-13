defmodule MyApp.Auth.Session do
  defstruct [:token, :user_id]

  def new(token) do
    %__MODULE__{token: token}
  end
end
