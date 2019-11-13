package app

import (
	"JSMPJ_jwt_final/validate"
	"log"
	"net/http"
	"strings"
)

var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// fmt.Println("We are in middle ware", validate.Names)
		notAuth := map[string]bool{"/login": true, "/sawdetails": true, "/account/user": true}
		if !notAuth[r.URL.Path] {
			if !VerifyToken(r) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Invalid JWT Token"))
				return
			}
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func VerifyToken(req *http.Request) bool {
	defer func() {
		if err := recover(); err != nil {
			log.Println("execption handled in VerifyToken : ", err)
		}
	}()

	//expecting `jwt token ` from Header key Authorization
	token := req.Header.Get("Authorization")

	// removing Bearer from the JWT token
	token = strings.TrimSpace(strings.Replace(token, "Bearer", "", -1))

	if token == "" {
		log.Println("empty JWT Token Header key Authorization : ", token)
		return false
	}

	status, err := validate.ValidateJWTToken(token)
	if err != nil {
		return false
	}
	return status
}
