package controllers

import (
	"net/http"

	"github.com/gozaddy/golang-auth-boilerplate/database"
	utils "github.com/gozaddy/golang-webdev-utils"
)

//GetProfiles returns all profiles stored in mongodb. You can use this endpoint to test some of the functionality like validate_jwt middleware, signing in and signing out.
func GetProfiles(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "GET",
		Origin:  "*",
	})

	profiles, err := database.GetAllProfiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.EncodeJSON(w, profiles)
}
