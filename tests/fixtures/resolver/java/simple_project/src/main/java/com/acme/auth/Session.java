package com.acme.auth;

public class Session {
    private String token;

    public Session(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
