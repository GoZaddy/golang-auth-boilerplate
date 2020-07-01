package controllers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/gozaddy/golang-auth-boilerplate/database"
	"github.com/gozaddy/golang-auth-boilerplate/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	utils "github.com/gozaddy/golang-webdev-utils"
)

//RegsiterWithEmailAndPassword registers a new user
func RegsiterWithEmailAndPassword(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "POST",
		Origin:  "*",
	})

	var u struct {
		Name     string `json:"name" validate:"required"`
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		name := r.FormValue("name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		u.Email = email
		u.Name = name
		u.Password = password

		if ok := utils.ValidateStructFromRequestBody(w, u); !ok {
			return
		}

	} else if r.Header.Get("Content-Type") == "application/json" {
		err := utils.DecodeJSONBody(w, r, u)
		if err != nil {
			var mr *utils.MalformedRequest
			if errors.As(err, &mr) {
				http.Error(w, mr.Msg, mr.Status)
			} else {
				log.Println(err.Error())
			}
			return
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.MinCost)
	if err != nil {
		http.Error(w, "Internal server error:"+err.Error(), http.StatusInternalServerError)
		return
	}
	profileID := primitive.NewObjectID().Hex()
	accountID := primitive.NewObjectID()
	account := models.Account{
		ID:         accountID,
		AuthMethod: models.EMAIL,
		EmailAuthDetails: models.EmailAuth{
			Email:    u.Email,
			Password: hashedPassword,
		},
		ProfileID: profileID,
	}

	profile := models.Profile{
		ID:          profileID,
		AccountID:   accountID,
		DisplayName: u.Name,
		Email:       u.Email,
	}

	if ok := utils.ValidateStructFromRequestBody(w, account); ok {
		if ok := utils.ValidateStructFromRequestBody(w, profile); ok {
			err = database.CreateAccount(account)
			if err != nil {
				if err.Error() == "User already exists" {
					http.Error(w, err.Error(), http.StatusConflict)
					return
				}
				http.Error(w, "Error creating account: "+err.Error(), http.StatusInternalServerError)
				return
			}

			err = database.CreateProfile(profile)
			if err != nil {
				http.Error(w, "Error creating profile: "+err.Error(), http.StatusInternalServerError)
				return
			}

			tokenDetails, err := utils.CreateToken(os.Getenv("ACCESS_TOKEN_KEY"), os.Getenv("REFRESH_TOKEN_KEY"), profileID)
			if err != nil {
				http.Error(w, "Couldn't create token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			err = utils.CreateAuth(profileID, tokenDetails, database.Store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			utils.EncodeJSON(w, map[string]string{
				"access_token":  tokenDetails.AccessToken,
				"refresh_token": tokenDetails.RefreshToken,
				"profile_id":    profileID,
			})
			w.WriteHeader(http.StatusCreated)
		} else {
			return
		}

	} else {
		return
	}

} //jwt

func LoginWithEmailAndPassword(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "POST",
		Origin:  "*",
	})

	var u struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		email := r.FormValue("email")
		password := r.FormValue("password")

		u.Email = email
		u.Password = password

		if ok := utils.ValidateStructFromRequestBody(w, u); !ok {
			return
		}
	} else if r.Header.Get("Content-Type") == "application/json" {
		err := utils.DecodeJSONBody(w, r, u)
		if err != nil {
			var mr *utils.MalformedRequest
			if errors.As(err, &mr) {
				http.Error(w, mr.Msg, mr.Status)
			} else {
				log.Println(err.Error())
			}
			return
		}
	}

	account, err := database.GetAccountWithEmail(u.Email)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			http.Error(w, "User does not exist", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println(account)
	ad := account.EmailAuthDetails
	err = bcrypt.CompareHashAndPassword(ad.Password, []byte(u.Password))
	if err != nil {
		http.Error(w, "Wrong password", http.StatusUnauthorized)
		return
	}
	tokenDetails, err := utils.CreateToken(os.Getenv("ACCESS_TOKEN_KEY"), os.Getenv("REFRESH_TOKEN_KEY"), ad.Email)
	if err != nil {
		http.Error(w, "Couldn't create token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = utils.CreateAuth(ad.Email, tokenDetails, database.Store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.EncodeJSON(w, map[string]string{
		"access_token":  tokenDetails.AccessToken,
		"refresh_token": tokenDetails.RefreshToken,
		"profile_id":    account.ProfileID,
	})

} //jwt

func Logout(w http.ResponseWriter, r *http.Request) {} //jwt

func LoginWithGoogle(w http.ResponseWriter, r *http.Request) {}

func LoginWithFacebook(w http.ResponseWriter, r *http.Request) {}

func LoginWithGithub(w http.ResponseWriter, r *http.Request) {}
