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
	router.HandleFunc("/api/register/email", controllers.RegisterWithEmailAndPassword).Methods("POST")
	router.HandleFunc("/api/login/email", controllers.LoginWithEmailAndPassword).Methods("POST")

	router.HandleFunc("/api/auth/google/get-url", controllers.GetGoogleLoginURL).Methods("GET")
	router.HandleFunc("/api/auth/google/callback", controllers.LoginWithGoogle).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", router))
}
