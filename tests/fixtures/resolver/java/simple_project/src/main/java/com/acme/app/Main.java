package com.acme.app;

import com.acme.auth.UserService;
import com.acme.db.DbClient;

public class Main {
    public static void main(String[] args) {
        DbClient db = new DbClient();
        UserService users = new UserService(db);
        users.createUser("admin");
    }
}
