package middleware

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gozaddy/golang-auth-boilerplate/database"
	utils "github.com/gozaddy/golang-webdev-utils"
	"github.com/joho/godotenv"
)

func init() {
	godotenv.Load(".env")
}

//ValidateJWT validates jwt token sent to the server
func ValidateJWT(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.InitEndPoint(w, r)
		authorizationHeader := r.Header.Get("Authorization")
		fmt.Println(authorizationHeader)
		bearerToken := strings.Split(authorizationHeader, " ")

		if len(bearerToken) == 2 && bearerToken[1] != "" {
			fmt.Print("token: ")
			fmt.Println(bearerToken[1])
			token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(os.Getenv("ACCESS_TOKEN_KEY")), nil
			})

			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
			}

			claims, ok := token.Claims.(jwt.MapClaims)

			if ok && token.Valid {
				accessUUID, ok := claims["access_uuid"].(string)
				if !ok {
					http.Error(w, "Invalid token", http.StatusUnauthorized)
					return
				}

				//check if user id exists in redis store
				userid, err := database.Store.Do("GET", accessUUID)
				if userid == nil || err != nil {
					http.Error(w, "Invalid token", http.StatusUnauthorized)
					return
				}
				re := r.WithContext(context.WithValue(r.Context(), utils.ContextKey("decoded"), claims))
				fmt.Println("token valid")
				next(w, re)

			}
		} else {
			http.Error(w, "A valid authorization header is required in the format of bearer <token>", http.StatusUnauthorized)
			return
		}

	})
}
