package keyinit

import (
	"crypto/rsa"
	"io/ioutil"
	"log"
	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	Token string `json:"token"`
}

var JwtToken string

type Claimsst struct {
	Name     string `json:"username"`
	Password string `json:"password"`
	jwt.StandardClaims
}

const (
	privKeyPath = "rsa/app.rsa"
	pubKeyPath  = "rsa/app.rsa.pub"
)

var (
	VerifyKeys *rsa.PublicKey
	SignKeys   *rsa.PrivateKey
)
var VerifyKey, SignKey []byte

func InitKeys() {
	var err error
	SignKey, err = ioutil.ReadFile(privKeyPath)
	SignKeys, err = jwt.ParseRSAPrivateKeyFromPEM(SignKey)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	VerifyKey, err = ioutil.ReadFile(pubKeyPath)
	VerifyKeys, err = jwt.ParseRSAPublicKeyFromPEM(VerifyKey)
	if err != nil {
		log.Fatal("Error reading public key")
		return
	}
}