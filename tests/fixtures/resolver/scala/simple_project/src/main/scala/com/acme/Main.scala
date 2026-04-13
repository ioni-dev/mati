package com.acme

import com.acme.auth.UserService
import com.acme.db.DbClient

object Main {
  def main(args: Array[String]): Unit = {
    val db = new DbClient()
    val users = new UserService(db)
    users.createUser("admin")
  }
}
