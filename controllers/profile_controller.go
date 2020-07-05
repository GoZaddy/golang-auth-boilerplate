package controllers

import (
	"net/http"

	"github.com/gozaddy/golang-auth-boilerplate/database"
	utils "github.com/gozaddy/golang-webdev-utils"
)

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
