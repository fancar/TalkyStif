package main

import (
	"net/http"
	"github.com/gorilla/sessions"
	"crypto/subtle"
)

var Store = sessions.NewCookieStore([]byte("t0p-s3cr3t"))

func runWebServer(a string) {
    r := NewRouter()
    http.Handle("/", r)
    go log.Fatal(http.ListenAndServe(a, nil))    
}

func InternalServerError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Internal server error"))
}

// ######################### BASIC AUTH TOOLS ######################################



func AuthRequired(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		user, pass, ok := r.BasicAuth()
		
		if !ok || !check_userpwd(user, pass) {
			http.Error(w, "Unauthorized.", 401)
			//http.Redirect(w, r, "/login", 302)
			return
		}
		handler.ServeHTTP(w, r)
	}
}

func check_userpwd(user string,pass string) bool {
	username := "enf0rter"
	password := "*jsn23L928Dq"

	return subtle.ConstantTimeCompare([]byte(user), []byte(username)) == 1 && subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1

}


// var users = map[string]string{
// 	"user1": "password1",
// 	"user2": "password2",
// }

// type Credentials struct {
// 	Password string `json:"password"`
// 	Username string `json:"username"`
// }




// ###################### /* END OF BASIC AUTH TOOLS */ ############################

