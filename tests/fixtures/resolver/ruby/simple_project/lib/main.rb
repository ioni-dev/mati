require_relative "auth"
require_relative "db"

class App
  def run
    auth = Auth.new
    db = Db.new
    auth.login("admin", db)
  end
end
