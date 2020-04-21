package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
)

// User ...
// Custom object which can be stored in the claims
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthToken ...
// This is what is retured to the user
type AuthToken struct {
	TokenType string `json:"token_type"`
	Token     string `json:"access_token"`
	ExpiresIn int64  `json:"expires_in"`
}

// AuthTokenClaim ...
// This is the cliam object which gets parsed from the authorization header
type AuthTokenClaim struct {
	*jwt.StandardClaims
	User
}

// ErrorMsg ...
// Custom error object
type ErrorMsg struct {
	Message string `json:"message"`
}

func authenticateHandler(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	expiresAt := time.Now().Add(time.Minute * 1).Unix()

	token := jwt.New(jwt.SigningMethodHS256)

	token.Claims = &AuthTokenClaim{
		&jwt.StandardClaims{
			ExpiresAt: expiresAt,
		},
		User{user.Username, user.Password},
	}

	tokenString, error := token.SignedString([]byte("secret"))
	if error != nil {
		fmt.Println(error)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthToken{
		Token:     tokenString,
		TokenType: "Bearer",
		ExpiresIn: expiresAt,
	})
}

func validateTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("secret"), nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(ErrorMsg{Message: error.Error()})
					return
				}
				if token.Valid {

					var user User
					mapstructure.Decode(token.Claims, &user)

					vars := mux.Vars(req)
					name := vars["userId"]
					if name != user.Username {
						json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token - Does not match UserID"})
						return
					}

					context.Set(req, "decoded", token.Claims)
					next(w, req)
				} else {
					json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
				}
			} else {
				json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
			}
		} else {
			json.NewEncoder(w).Encode(ErrorMsg{Message: "An authorization header is required"})
		}
	})
}

func users(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	var user User
	mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	json.NewEncoder(w).Encode(user)
}

func main() {
	router := mux.NewRouter()
	fmt.Println("Application Starting ...")
	router.HandleFunc("/authenticate", authenticateHandler).Methods("POST")
	router.HandleFunc("/users/{userId}/credentials", validateTokenMiddleware(users)).Methods("GET")
	log.Fatal(http.ListenAndServe(":3000", router))
}
