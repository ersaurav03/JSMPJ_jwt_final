package validate

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	privKeyPath = "app.rsa"
	pubKeyPath  = "app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)
var VerifyKey, SignKey []byte

func InitKeys() {
	var err error
	SignKey, err = ioutil.ReadFile(privKeyPath)
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(SignKey)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	VerifyKey, err = ioutil.ReadFile(pubKeyPath)
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(VerifyKey)
	if err != nil {
		log.Fatal("Error reading public key")
		return
	}
}

//STRUCT DEFINITIONS

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

type Token struct {
	Token string `json:"token"`
}

var jwtToken string

type claimsst struct {
	Name     string `json:"username"`
	Password string `json:"password"`
	// Role string `json:"role"`
	jwt.StandardClaims
}

func Validate(w http.ResponseWriter, r *http.Request) {
	status, err := ValidateJWTToken(jwtToken)
	if status == true && err == nil {
		response := Response{"Gained access to protected resource"}
		JsonResponse(response, w)
	} else {
		fmt.Println("fail")
	}
}

func Check(w http.ResponseWriter, r *http.Request) {
	status, err := ValidateJWTToken(jwtToken)
	if status == true && err == nil {
		response := Response{"Gained access to protected resource in check"}
		JsonResponse(response, w)
	} else {
		response := Response{"Failed access to protected resource"}
		JsonResponse(response, w)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user UserCredentials
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Error in request")
		return
	}

	fmt.Println(user.Username, user.Password)
	if strings.ToLower(user.Username) != "alexcons" || user.Password != "kappa123" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Println("Error logging in")
		fmt.Fprint(w, "Invalid credentials")
		return
	}

	claims := claimsst{
		Name:     user.Username,
		Password: user.Password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "JSMPJ-Corporation",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	fmt.Println("Token is", token)
	tokenString, err := token.SignedString(signKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while signing the token")
		log.Printf("Error signing token: %v\n", err)
	}

	fmt.Println("Token String is ", tokenString)

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: time.Now().Add(5 * time.Minute),
	})

	jwtToken = tokenString
	response := Token{tokenString}
	JsonResponse(response, w)
}
func ValidateJWTToken(jwtToken string) (bool, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &claimsst{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return verifyKey, nil
	})

	//Malformed token,
	if err != nil || !token.Valid {
		return false, errors.New("Token is not valid")
	}

	claim, ok := token.Claims.(*claimsst)
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