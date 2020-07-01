package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gozaddy/golang-auth-boilerplate/controllers"
	"github.com/gozaddy/golang-auth-boilerplate/database"
)

func init() {
	database.Connect()
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/api/register/email", controllers.RegsiterWithEmailAndPassword).Methods("POST")
	router.HandleFunc("/api/login/email", controllers.LoginWithEmailAndPassword).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
