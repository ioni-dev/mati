class Db
  def initialize
    @dsn = "localhost:5432"
  end

  def query(sql)
    puts sql
  end
end
