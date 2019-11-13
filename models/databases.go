package models

import (
	"JSMPJ_jwt_final/keyinit"
	"JSMPJ_jwt_final/validate"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
)

var db *gorm.DB

type TestUser struct {
	gorm.Model
	Email    string `json:"Email"`
	Password string `json:"Password"`
}

func DBinit() {
	username, dbName, dbHost, dbport, dbpassword := Setdbvars()
	dbUri := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s", dbHost, dbport, username, dbName, dbpassword)
	conn, err := gorm.Open("postgres", dbUri)
	if err != nil {
		fmt.Print(err)
	}
	db = conn
	db.AutoMigrate(&TestUser{})
	fmt.Println("Database initilization done successfully")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("there is an error")
		fmt.Fprintf(w, "There is a problem to read a body")
	}
	var TestUsers TestUser
	err = json.Unmarshal(body, &TestUsers)
	if err != nil {
		fmt.Println("Problem in unmarshal the response")
		fmt.Fprintf(w, "Problem in unmarshiling the response")
	}
	db.Save(&TestUser{Email: TestUsers.Email, Password: TestUsers.Password})
	fmt.Fprintf(w, "New User created successfully")
	claims := keyinit.Claimsst{
		Name:     TestUsers.Email,
		Password: TestUsers.Password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "JSMPJ-Corporation",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	fmt.Println("Token is", token)
	tokenString, err := token.SignedString(keyinit.SignKeys)

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

	keyinit.JwtToken = tokenString
	response := keyinit.Token{tokenString}

	validate.JsonResponse(response, w)
	fmt.Println("New user created successfully")
}

func SawDetail(w http.ResponseWriter, r *http.Request) {
	username, dbName, dbHost, dbport, dbpassword := Setdbvars()
	dbUri := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s", dbHost, dbport, username, dbName, dbpassword)
	conn, err := gorm.Open("postgres", dbUri)
	if err != nil {
		fmt.Print(err)
	}
	db = conn
	var TestUsers []TestUser
	db.Find(&TestUsers)
	if len(TestUsers) == 0 {
		fmt.Fprintf(w, "We can not read from database")
	} else {
		json.NewEncoder(w).Encode(TestUsers)
	}
}
func Setdbvars() (string, string, string, string, string) {
	e := godotenv.Load()
	if e != nil {
		fmt.Print(e)
	}
	username := os.Getenv("db_user")
	password := os.Getenv("db_pass")
	dbName := os.Getenv("db_name")
	dbHost := os.Getenv("db_host")
	dbport := os.Getenv("db_port")
	dbpassword := password + "#"
	return username, dbName, dbHost, dbport, dbpassword
}
