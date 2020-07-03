package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/gozaddy/golang-auth-boilerplate/database"
	"github.com/gozaddy/golang-auth-boilerplate/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	utils "github.com/gozaddy/golang-webdev-utils"
)

var conf *oauth2.Config

func init() {
	conf = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/api/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

//RegsiterWithEmailAndPassword registers a new user
func RegisterWithEmailAndPassword(w http.ResponseWriter, r *http.Request) {
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
	profileID := primitive.NewObjectID()
	accountID := primitive.NewObjectID()
	account := models.Account{
		ID:            accountID,
		AuthProviders: []string{models.EMAIL},
		Email:         u.Email,
		EmailAuthDetails: &models.EmailAuth{
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

			tokenDetails, err := utils.CreateToken(os.Getenv("ACCESS_TOKEN_KEY"), os.Getenv("REFRESH_TOKEN_KEY"), profileID.Hex())
			if err != nil {
				http.Error(w, "Couldn't create token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			err = utils.CreateAuth(profileID.Hex(), tokenDetails, database.Store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusCreated)
			utils.EncodeJSON(w, map[string]string{
				"access_token":  tokenDetails.AccessToken,
				"refresh_token": tokenDetails.RefreshToken,
				"profile_id":    profileID.Hex(),
			})

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
	tokenDetails, err := utils.CreateToken(os.Getenv("ACCESS_TOKEN_KEY"), os.Getenv("REFRESH_TOKEN_KEY"), account.Email)
	if err != nil {
		http.Error(w, "Couldn't create token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = utils.CreateAuth(account.Email, tokenDetails, database.Store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.EncodeJSON(w, map[string]string{
		"access_token":  tokenDetails.AccessToken,
		"refresh_token": tokenDetails.RefreshToken,
		"profile_id":    account.ProfileID.Hex(),
	})

} //jwt

func GetGoogleLoginURL(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "GET",
		Origin:  "*",
	})

	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.Write([]byte("<html><title>Golang Google</title> <body> <a href='" + conf.AuthCodeURL(state) + "'><button>Login with Google!</button> </a> </body></html>"))
	utils.EncodeJSON(w, map[string]string{
		"google_login_url": conf.AuthCodeURL(state),
	})
}
func Logout(w http.ResponseWriter, r *http.Request) {} //jwt

func LoginWithGoogle(w http.ResponseWriter, r *http.Request) {
	savedState, err := r.Cookie("state")
	if err != nil || savedState.Value != r.URL.Query().Get("state") {
		fmt.Println(savedState)
		http.Error(w, "Invalid state", http.StatusUnauthorized)
		return
	}

	token, err := conf.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	client := conf.Client(context.Background(), token)
	profile, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	defer profile.Body.Close()
	var userDetails struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	json.NewDecoder(profile.Body).Decode(&userDetails)
	fmt.Println(userDetails)

	accountID := primitive.NewObjectID()
	profileID := primitive.NewObjectID()
	newAccount := models.Account{
		ID:            accountID,
		Email:         userDetails.Email,
		AuthProviders: []string{models.GOOGLE},
		GoogleAuthDetails: &models.GoogleAuth{
			ID: userDetails.Sub,
		},
		ProfileID: profileID,
	}

	newProfile := models.Profile{
		ID:          profileID,
		AccountID:   accountID,
		Email:       userDetails.Email,
		DisplayName: userDetails.Name,
	}

	if ok := utils.ValidateStructFromRequestBody(w, newAccount); ok {
		if ok := utils.ValidateStructFromRequestBody(w, newProfile); ok {
			err = database.CreateAccount(newAccount)
			if err != nil {
				if err.Error() == "User already exists" {
					fmt.Println("user already exists so logging in straight")
					tokenDetails, err := utils.CreateToken(os.Getenv("ACCESS_TOKEN_KEY"), os.Getenv("REFRESH_TOKEN_KEY"), profileID.Hex())
					if err != nil {
						http.Error(w, "Couldn't create token: "+err.Error(), http.StatusInternalServerError)
						return
					}

					err = utils.CreateAuth(profileID.Hex(), tokenDetails, database.Store)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					utils.EncodeJSON(w, map[string]string{
						"access_token":  tokenDetails.AccessToken,
						"refresh_token": tokenDetails.RefreshToken,
						"profile_id":    profileID.Hex(),
					})
					w.WriteHeader(http.StatusCreated)
					return
				}
				http.Error(w, "Error creating account: "+err.Error(), http.StatusInternalServerError)
				return
			}

			err = database.CreateProfile(newProfile)
			if err != nil {
				http.Error(w, "Error creating profile: "+err.Error(), http.StatusInternalServerError)
				return
			}

			tokenDetails, err := utils.CreateToken(os.Getenv("ACCESS_TOKEN_KEY"), os.Getenv("REFRESH_TOKEN_KEY"), profileID.Hex())
			if err != nil {
				http.Error(w, "Couldn't create token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			err = utils.CreateAuth(profileID.Hex(), tokenDetails, database.Store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			utils.EncodeJSON(w, map[string]string{
				"access_token":  tokenDetails.AccessToken,
				"refresh_token": tokenDetails.RefreshToken,
				"profile_id":    profileID.Hex(),
			})
			w.WriteHeader(http.StatusCreated)
		} else {
			return
		}

	} else {
		return
	}

	/*data, _ := ioutil.ReadAll(profile.Body)
	fmt.Println("Profile Body: ", string(data))*/

}

func LoginWithFacebook(w http.ResponseWriter, r *http.Request) {}

func LoginWithGithub(w http.ResponseWriter, r *http.Request) {}
