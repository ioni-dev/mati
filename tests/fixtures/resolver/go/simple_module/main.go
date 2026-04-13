package main

import (
	"fmt"
	"github.com/example/simple/auth"
	"github.com/example/simple/db"
)

func main() {
	u := auth.NewUser("admin")
	c := db.NewClient()
	fmt.Println(u, c)
}
