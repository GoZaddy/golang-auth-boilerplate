package main

import (
	"log"
	"net/http"

	"github.com/gozaddy/golang-auth-boilerplate/middleware"

	"github.com/gorilla/mux"
	"github.com/gozaddy/golang-auth-boilerplate/controllers"
	"github.com/gozaddy/golang-auth-boilerplate/database"
)

func init() {
	database.Connect()
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/api/auth/register/email", controllers.RegisterWithEmailAndPassword).Methods("POST")
	router.HandleFunc("/api/auth/login/email", controllers.LoginWithEmailAndPassword).Methods("POST")

	router.HandleFunc("/api/auth/google/get-url", controllers.GetGoogleLoginURL).Methods("GET")
	router.HandleFunc("/api/auth/google/callback", controllers.LoginWithGoogle).Methods("GET")

	router.HandleFunc("/api/auth/github/get-url", controllers.GetGithubLoginURL).Methods("GET")
	router.HandleFunc("/api/auth/github/callback", controllers.LoginWithGithub).Methods("GET")

	router.HandleFunc("/api/token/refresh", controllers.RefreshToken).Methods("POST")

	router.HandleFunc("/api/auth/logout", middleware.ValidateJWT(controllers.Logout)).Methods("POST", "OPTIONS")

	router.HandleFunc("/api/profiles", middleware.ValidateJWT(controllers.GetProfiles)).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", router))
}
