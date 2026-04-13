package com.acme.db

class DbClient {
  def execute(sql: String): Unit = {
    println(s"Executing: $sql")
  }
}
