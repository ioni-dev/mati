package com.acme.auth

import com.acme.db.DbClient

class UserService(db: DbClient) {
  def createUser(name: String): Unit = {
    db.execute(s"INSERT INTO users (name) VALUES ('$name')")
  }
}
