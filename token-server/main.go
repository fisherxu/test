package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

func generateToken() string {
	expiresAt := time.Now().Add(time.Hour * 24).Unix()

	token := jwt.New(jwt.SigningMethodHS256)

	token.Claims = jwt.StandardClaims{
		ExpiresAt: expiresAt,
	}

	tokenString, _ := token.SignedString([]byte("secret"))

	fmt.Println(tokenString)
	return tokenString
}

func generateTokenTest() string {
	expiresAt := time.Now().Add(time.Hour * 24).Unix()

	token := jwt.New(jwt.SigningMethodHS256)

	token.Claims = jwt.StandardClaims{
		ExpiresAt: expiresAt,
	}

	tokenString, _ := token.SignedString([]byte("secretTest"))

	return tokenString
}

func refreshToken() string {
	claims := &jwt.StandardClaims{}
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))
	return tokenString
}

func verifyToken(w http.ResponseWriter, r *http.Request) {
	authorizationHeader := r.Header.Get("authorization")
	if authorizationHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}
	bearerToken := strings.Split(authorizationHeader, " ")
	if len(bearerToken) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}
	token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte("secret"), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}
	w.Write([]byte(fmt.Sprintf("Welcome")))
}

func getCA(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf("CA will be returned")))
}

func main() {
	generateToken()

	t := time.NewTicker(time.Hour * 12)
	go func() {
		for {
			select {
			case <-t.C:
				refreshToken()
			}
		}
	}()

	router := mux.NewRouter()
	router.HandleFunc("/certs", verifyToken).Methods("GET")
	router.HandleFunc("/ca", getCA).Methods("GET")
	go func() {
		log.Fatal(http.ListenAndServe(":3000", router))
	}()

	go func() {
		time.Sleep(time.Second * 2)

		client := &http.Client{}
		req, _ := http.NewRequest("GET", "http://localhost:3000/certs", nil)

		tokenString := generateToken()
		// Create a Bearer string by appending string access token
		var bearer = "Bearer " + tokenString
		req.Header.Set("Authorization", bearer)

		res, err := client.Do(req)

		if err != nil {
			fmt.Println("Error: %s", err.Error())
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(body))

		req, _ = http.NewRequest("GET", "http://localhost:3000/ca", nil)
		res, err = client.Do(req)

		if err != nil {
			fmt.Println("Error: %s", err.Error())
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(body))

	}()
	time.Sleep(time.Hour * 30)
}
