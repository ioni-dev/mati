package com.acme.auth;

import com.acme.db.DbClient;

public class UserService {
    private final DbClient db;

    public UserService(DbClient db) {
        this.db = db;
    }

    public void createUser(String name) {
        db.execute("INSERT INTO users (name) VALUES ('" + name + "')");
    }
}
