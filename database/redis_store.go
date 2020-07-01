package database

import (
	"fmt"
	"log"

	"github.com/gomodule/redigo/redis"
)

var Store redis.Conn

func init() {
	conn, err := redis.DialURL("redis://localhost")

	if err != nil {
		fmt.Println("error with redis")
		log.Fatal(err)
	}
	Store = conn
}
