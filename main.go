package main

import (
	"JSMPJ_jwt_final/app"
	"JSMPJ_jwt_final/validate"
	"log"
	"net/http"

	"JSMPJ_jwt_final/keyinit"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func StartServer() {
	newRouter := mux.NewRouter()
	origins := handlers.AllowedOrigins([]string{"*"})
	headers := handlers.AllowedHeaders([]string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "PUT", "POST", "DELETE"})
	newRouter.HandleFunc("/login", validate.LoginHandler).Methods("POST")
	newRouter.HandleFunc("/resource/", validate.Validate).Methods("GET")
	newRouter.HandleFunc("/check/", validate.Check).Methods("GET")
	newRouter.Use(app.JwtAuthentication)
	log.Println("Now listening...")
	log.Fatal(http.ListenAndServe(":8001", handlers.CORS(origins, methods, headers)(newRouter)))
}
func main() {
	keyinit.InitKeys()
	StartServer()
}
