package auth

import "github.com/example/simple/db"

type User struct {
	Name string
	DB   *db.Client
}

func NewUser(name string) *User {
	return &User{Name: name}
}
