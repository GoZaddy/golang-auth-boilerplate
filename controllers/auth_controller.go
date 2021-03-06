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
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/dgrijalva/jwt-go"
	"github.com/gozaddy/golang-auth-boilerplate/database"
	"github.com/gozaddy/golang-auth-boilerplate/models"
	"golang.org/x/crypto/bcrypt"

	utils "github.com/gozaddy/golang-webdev-utils"
)

var conf *oauth2.Config
var githubConf *oauth2.Config

func init() {
	//The oauth config for google sign in
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

	//The oauth config for github sign in
	githubConf = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/api/auth/github/callback",
		Scopes: []string{
			"read:user", "user:email",
		},
		Endpoint: github.Endpoint,
	}
}

//RegisterWithEmailAndPassword registers a new user using their email and password.
//A StatusConflict code is returned if the user already exists and a StatusBadRequest is returned if the client input fails validation
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
		fmt.Println(r.Header.Get("Content-Type"))
		err := utils.DecodeJSONBody(w, r, &u)
		fmt.Println(u)
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
	profileID, err := database.CreateAccountWithEmailDetails(u.Email, hashedPassword, u.Name)
	if err != nil {
		if err.Error() == "User already exists" {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
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

} //jwt

//LoginWithEmailAndPassword logs in a user using their email and password
//A StatusBadRequest is returned if the client input fails validation and a StatusNotFound is returned if the user doesn't exist
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
		err := utils.DecodeJSONBody(w, r, &u)
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

//GetGoogleLoginURL is a GET endpoint used by the client to return a url which can be used to sign in with the user's google account
//The same url cannot be used twice as each url generated is unique
//Currently this endpoint returns a button that prompt Google sign in when clicked. Uncomment the last block of code to return the url in a JSON
func GetGoogleLoginURL(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "GET",
		Origin:  "*",
	})

	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     "google-auth-state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.Write([]byte("<html><title>Golang Google</title> <body> <a href='" + conf.AuthCodeURL(state) + "'><button>Login with Google!</button> </a> </body></html>"))
	/*utils.EncodeJSON(w, map[string]string{
		"google_login_url": conf.AuthCodeURL(state),
	})*/
}

//GetGithubLoginURL is a GET endpoint used by the client to return a url which can be used to sign in with the user's github account
//The same url cannot be used twice as each url generated is unique
//Currently this endpoint returns a button that prompt Github sign in when clicked. Uncomment the last block of code to return the url in a JSON
func GetGithubLoginURL(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "GET",
		Origin:  "*",
	})

	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     "github-auth-state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	//For testing
	//w.Write([]byte("<html><title>Golang Github</title> <body> <a href='" + githubConf.AuthCodeURL(state) + "'><button>Login with Github!</button> </a> </body></html>"))
	utils.EncodeJSON(w, map[string]string{
		"github_login_url": githubConf.AuthCodeURL(state),
	})
}

//Logout endpoint must be used with the validateJWT middleware as it gets the tokenClaims from there
//It deletes the access token from Redis thereby rendering an access token invalid once a user logs out
func Logout(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "POST",
		Origin:  "*",
	})
	tokenClaims, ok := r.Context().Value(utils.ContextKey("decoded")).(jwt.MapClaims)
	fmt.Println(r.Context().Value(utils.ContextKey("decoded")))
	if !ok {
		http.Error(w, "Internal server error: could not properly decode token claims from token", http.StatusInternalServerError)
		return
	}

	_, err := database.Store.Do("DEL", tokenClaims["access_uuid"].(string))

	if err != nil {
		http.Error(w, "Error logging out", http.StatusInternalServerError)
		return
	}

	utils.EncodeJSON(w, map[string]string{
		"message": "Successfully logged out!",
	})
} //jwt

//LoginWithGoogle endpoint verifies that the state in the URL is correct by comparing it against the state stored in a cookie. It then gets the necessary user information from google and creates an account for the user if the user is new or log them in.
//After a successful login, an access token,refresh tokens and the profile ID of the user will be returned in a JSON
func LoginWithGoogle(w http.ResponseWriter, r *http.Request) {
	savedState, err := r.Cookie("google-auth-state")
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
	var userDetails models.GoogleUserDetails
	json.NewDecoder(profile.Body).Decode(&userDetails)
	fmt.Println(userDetails)

	profileID, err := database.CreateAccountWithOauthDetails(userDetails)
	if err != nil {
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
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

}

//LoginWithGithub endpoint verifies that the state in the URL is correct by comparing it against the state stored in a cookie. It then gets the necessary user information from google and creates an account for the user if the user is new or log them in.
//After a successful login, an access token,refresh tokens and the profile ID of the user will be returned in a JSON
func LoginWithGithub(w http.ResponseWriter, r *http.Request) {
	savedState, err := r.Cookie("github-auth-state")
	if err != nil || savedState.Value != r.URL.Query().Get("state") {
		fmt.Println(savedState)
		http.Error(w, "Invalid state", http.StatusUnauthorized)
		return
	}
	fmt.Println("code: " + r.URL.Query().Get("code"))
	token, err := githubConf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Print("token: ")
	fmt.Println(token)

	client := githubConf.Client(context.Background(), token)
	profile, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer profile.Body.Close()

	var githubDetails models.GithubUserDetails
	json.NewDecoder(profile.Body).Decode(&githubDetails)

	fmt.Println(githubDetails)

	profileID, err := database.CreateAccountWithOauthDetails(githubDetails)
	if err != nil {
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
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

}

//RefreshToken endpoint is used to refresh JWTs, the refresh token must be passed in the request body as refresh_token
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	utils.InitEndpointWithOptions(w, r, utils.InitEndpointOptions{
		Methods: "POST",
		Origin:  "*",
	})

	var refreshTokenStruct struct {
		RefreshToken string `json:"refresh_token"`
	}

	err := utils.DecodeJSONBody(w, r, &refreshTokenStruct)
	if err != nil {
		var mr *utils.MalformedRequest
		if errors.As(err, &mr) {
			http.Error(w, mr.Msg, mr.Status)
		} else {
			log.Println(err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}
	token, err := jwt.Parse(refreshTokenStruct.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_TOKEN_KEY")), nil
	})

	if err != nil {
		http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		return
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUUID, ok := claims["refresh_uuid"].(string)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnprocessableEntity)
			return
		}

		userid, ok := claims["user_id"].(string)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnprocessableEntity)
			return
		}

		//delete the previous refresh token
		_, err = database.Store.Do("DEL", refreshUUID)
		if err != nil {
			http.Error(w, "Error deleting previous refresh token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		//create new pairs of refresh and access tokens
		tokenDetails, err := utils.CreateToken(os.Getenv("ACCESS_TOKEN_KEY"), os.Getenv("REFRESH_TOKEN_KEY"), userid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		//store new token details in redis store
		err = utils.CreateAuth(userid, tokenDetails, database.Store)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		utils.EncodeJSON(w, map[string]string{
			"access_token":  tokenDetails.AccessToken,
			"refresh_token": tokenDetails.RefreshToken,
		})

	}

}
