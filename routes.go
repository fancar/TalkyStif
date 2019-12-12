package main

import (
	//"strconv"
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"

//	"../middleware"
	//"../models"
	// "../sessions"
	// "../utils"
)



func NewRouter() *mux.Router {
	r := mux.NewRouter()
	//r.HandleFunc("/", AuthRequired(indexGetHandler)).Methods("GET")
	r.HandleFunc("/", indexGetHandler).Methods("GET")
	
	//r.HandleFunc("/info", infoGetHandler).Methods("GET")
	r.HandleFunc("/info", AuthRequired(infoGetHandler)).Methods("GET")
	r.HandleFunc("/sniffers", AuthRequired(SniffersGetHandler)).Methods("GET")
	//r.HandleFunc("/sniffers", SniffersGetHandler).Methods("GET")

	r.HandleFunc("/login", loginGetHandler).Methods("GET")
	//r.HandleFunc("/login", loginPostHandler).Methods("POST")
	//r.HandleFunc("/logout", logoutGetHandler).Methods("GET")
	//r.HandleFunc("/register", registerGetHandler).Methods("GET")
	//r.HandleFunc("/register", registerPostHandler).Methods("POST")
	//fs := http.FileServer(http.Dir("./static/"))
	//r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	//r.HandleFunc("/{username}",
	//	middleware.AuthRequired(userGetHandler)).Methods("GET")
	return r
}


func indexGetHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there !\n This is a sniffer's collector (named Talky).")
}

func infoGetHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "some statistics will be here\n")
}

func loginGetHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Auth is Required!")
}

// func SniffersGetHandler(w http.ResponseWriter, r *http.Request) {
// 	    w.Header().Set("Content-Type", "application/json")
//         main_cache.Lock()
//         snifs := main_cache.snifs

//         type keyvalue map[string]string
//         keyvalueslice := make([]keyvalue,0)
        
//         for _,vi := range snifs {
//         	data := map[string]string{
//         		"id": vi.id, //strconv.FormatInt(vi.id, 10),
//         		"ip": vi.ip, // strconv.FormatInt(vi.ip, 10),
//         		"macs": strconv.Itoa(len(vi.macs)),
//         		"post_macs": strconv.FormatInt(vi.post_macs, 10),
//         		"new_macs": strconv.FormatInt(vi.new_macs, 10),
//         		"pps": strconv.FormatInt(vi.pps, 10),
//         		"pct_cnt": strconv.FormatInt(vi.packets_period, 10),
//         		"total_cnt": strconv.FormatInt(vi.packets_total, 10),
//         		"ts_first": strconv.FormatInt(vi.first_time, 10),
//         		"ts_last": strconv.FormatInt(vi.update_time/1000000000, 10),
//         		//"ts_fist": vi.first_time,
//         		//"ts_last": vi.update_time,
//         	}

//         	keyvalueslice = append(keyvalueslice,data)
//         }
//         main_cache.Unlock()

//         j, err := json.Marshal(keyvalueslice)
            
//         if err != nil{
//         	log.Error("json err: ",err)
//         } else { w.Write(j) }

// }

func SniffersGetHandler(w http.ResponseWriter, r *http.Request) {
	    w.Header().Set("Content-Type", "application/json")

	    snifs := GetSnifs()
	    result,err := json.Marshal(snifs)
            
        if err == nil{
        	w.Write(result)
        } else {
        	w.WriteHeader(http.StatusInternalServerError)
        	w.Write([]byte(err.Error()))
        }
}






// func userGetHandler(w http.ResponseWriter, r *http.Request) {
// 	session, _ := sessions.Store.Get(r, "session")
// 	untypedUserId := session.Values["user_id"]
// 	currentUserId, ok := untypedUserId.(int64)
// 	if !ok {
// 		utils.InternalServerError(w)
// 		return
// 	}
// 	vars := mux.Vars(r)
// 	username := vars["username"]
// 	user, err := models.GetUserByUsername(username)
// 	if err != nil {
// 		utils.InternalServerError(w)
// 		return
// 	}
// 	userId, err := user.GetId()
// 	if err != nil {
// 		utils.InternalServerError(w)
// 		return
// 	}
// 	updates, err := models.GetUpdates(userId)
// 	if err != nil {
// 		utils.InternalServerError(w)
// 		return
// 	}
// 	utils.ExecuteTemplate(w, "index.html", struct {
// 		Title string
// 		Updates []*models.Update
// 		DisplayForm bool
// 		} {
// 		Title: username,
// 		Updates: updates,
// 		DisplayForm: currentUserId == userId,
// 	})
// }

// func loginGetHandler(w http.ResponseWriter, r *http.Request) {
// 	utils.ExecuteTemplate(w, "login.html", nil)
// }

// func loginPostHandler(w http.ResponseWriter, r *http.Request) {
// 	r.ParseForm()
// 	username := r.PostForm.Get("nickname")
// 	password := r.PostForm.Get("password")
// 	user, err := models.AuthenticateUser(username, password)
// 	if err != nil {
// 		switch err {
// 		case models.ErrUserNotFound:
// 			utils.ExecuteTemplate(w, "auth/login.html", "unknown user")
// 		case models.ErrInvalidLogin:
// 			utils.ExecuteTemplate(w, "auth/login.html", "invalid login")
// 		default:
// 			utils.InternalServerError(w)
// 		}
// 		return
// 	}
// 	userId, err := user.GetId()
// 	if err != nil {
// 		utils.InternalServerError(w)
// 		return
// 	}
// 	session, _ := sessions.Store.Get(r, "session")
// 	session.Values["user_id"] = userId
// 	session.Save(r, w)
// 	http.Redirect(w, r, "/", 302)
// }

// func logoutGetHandler(w http.ResponseWriter, r *http.Request) {
// 	session, _ := sessions.Store.Get(r, "session")
// 	delete(session.Values, "user_id")
// 	session.Save(r, w)
// 	http.Redirect(w, r, "/login", 302)
// }

// func registerGetHandler(w http.ResponseWriter, r *http.Request) {
// 	utils.ExecuteTemplate(w, "register.html", nil)
// }

// func registerPostHandler(w http.ResponseWriter, r *http.Request) {
// 	r.ParseForm()
// 	username := r.PostForm.Get("username")
// 	password := r.PostForm.Get("password")
// 	err := models.RegisterUser(username, password)
// 	if err == models.ErrUsernameTaken {
// 		utils.ExecuteTemplate(w, "register.html", "username taken")
// 		return
// 	} else if err != nil {
// 		utils.InternalServerError(w)
// 		return
// 	}
// 	http.Redirect(w, r, "/login", 302)
// }
