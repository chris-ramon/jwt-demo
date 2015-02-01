package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var privKey []byte

func init() {
	key, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal(err)
	}
	privKey = key
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	jwtToken := jwt.New(jwt.SigningMethodHS256)
	jwtToken.Claims["exp"] = time.Now().Add(time.Second * 1).Unix()
	jwtToken.Claims["user_id"] = 321
	jsonWebToken, err := jwtToken.SignedString(privKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write([]byte(jsonWebToken))
}

func UsersIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("[]"))
}

func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var defaultKeyFunc jwt.Keyfunc = func(*jwt.Token) (interface{}, error) {
			return privKey, nil
		}
		jsonWebTokenParsed, err := jwt.Parse(r.Header.Get("jwt"), defaultKeyFunc)
		if err != nil || !jsonWebTokenParsed.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func main() {
	http.HandleFunc("/auth", AuthHandler)
	http.HandleFunc("/users", JWTMiddleware(UsersIndex))
	http.ListenAndServe(":8080", nil)
}
