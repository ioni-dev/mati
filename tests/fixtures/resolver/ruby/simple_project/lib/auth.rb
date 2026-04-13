require_relative "db"

class Auth
  def login(username, db)
    db.query("SELECT * FROM users WHERE name = '#{username}'")
  end
end
