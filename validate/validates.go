package validate

import (
	"JSMPJ_jwt_final/keyinit"
	"encoding/json"
	"errors"
	"fmt"

	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"
)

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Data string `json:"data"`
}

func Validate(w http.ResponseWriter, r *http.Request) {
	status, err := ValidateJWTToken(keyinit.JwtToken)
	if status == true && err == nil {
		response := Response{"Gained access to protected resource"}
		JsonResponse(response, w)
	} else {
		fmt.Println("fail")
	}
}

func Check(w http.ResponseWriter, r *http.Request) {
	status, err := ValidateJWTToken(keyinit.JwtToken)
	if status == true && err == nil {
		response := Response{"Gained access to protected resource in check"}
		JsonResponse(response, w)
	} else {
		response := Response{"Failed access to protected resource"}
		JsonResponse(response, w)
	}
}

func ValidateJWTToken(jwtToken string) (bool, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &keyinit.Claimsst{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return keyinit.VerifyKeys, nil
	})

	//Malformed token,
	if err != nil || !token.Valid {
		return false, errors.New("Token is not valid")
	}

	claim, ok := token.Claims.(*keyinit.Claimsst)
	if !ok {
		fmt.Printf("%v %v %v\n", claim.Name, claim.StandardClaims.ExpiresAt, claim.Issuer)
		return false, errors.New("Invalid JWT Token Claim")
	}

	if claim.Issuer != "JSMPJ-Corporation" {
		return false, errors.New("Invaid JWT Issuer")
	}

	if claim.ExpiresAt < time.Now().Unix() {
		return false, errors.New("JWT Token Expired")
	}

	return true, nil
}
func JsonResponse(response interface{}, w http.ResponseWriter) {
	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}
