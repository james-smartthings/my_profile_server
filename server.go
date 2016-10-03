package main

import (
	// Standard library packages
	"fmt"
	"net/http"
	"time"
	"os"
	"bytes"
	"strings"

	// Third party packages
	"github.com/pborman/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"github.com/gorilla/securecookie"
)

// Globals
const COOKIE_NAME = "st_uuid"
var cookieJar map[string]*oauth2.Token
var hashKey = []byte( os.Getenv("DEV_PROFILE_CLIENT_HASH_KEY") )
var blockKey = []byte( os.Getenv("DEV_PROFILE_CLIENT_BLOCK_KEY") )
var s = securecookie.New(hashKey, blockKey)

// Your credentials should be obtained from the Google
// Developer Console (https://console.developers.google.com).
var oauthCfg = &oauth2.Config{
	ClientID: os.Getenv("DEV_PROFILE_CLIENT_GOOGLE_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("DEV_PROFILE_CLIENT_GOOGLE_OAUTH_CLIENT_SECRET"),
	RedirectURL:  "http://localhost:8000/auth/google/callback",
	Scopes: []string{"profile"},
	Endpoint: google.Endpoint,
}

// Handlers
func oauthRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w,r, oauthCfg.AuthCodeURL("state"), http.StatusTemporaryRedirect)
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	token, err := oauthCfg.Exchange(oauth2.NoContext, code)
	if err != nil {
		// Invalid Token
		http.Redirect(w, r, "https://graph.api.smartthings.com/register/index", http.StatusTemporaryRedirect)
	}
	//Valid Token. Generate new cookie & save it
	if cookieJar == nil {
		cookieJar = make(map[string]*oauth2.Token)
	}
	buildAndSaveCookie(w,r, token)
	http.Redirect(w, r, "http://localhost:3000", http.StatusTemporaryRedirect)
}

func buildAndSaveCookie(w http.ResponseWriter, r *http.Request, token *oauth2.Token) {

	expire := time.Now().Add(365 * 24 * time.Hour)
	guid := uuid.New()
	value := map[string]string{
		"uuid": guid,
	}
	if encoded, err := s.Encode(COOKIE_NAME, value); err == nil {
		newCookie := &http.Cookie{
			Name: COOKIE_NAME,
			Value: encoded,
			Domain: "localhost",
			Path: "/",
			Expires: expire,
		}
		http.SetCookie(w, newCookie)
		cookieJar[guid] = token
	}
}

func isLoggedInHandler(w http.ResponseWriter, r *http.Request) {
	var buffer bytes.Buffer
	response := ""
	jsonString := ""
	callbackName := strings.Join(r.URL.Query()["callback"], "")

	//Check to see if cookie exists If so Decode and return true, else return false
	if cookie, err := r.Cookie(COOKIE_NAME); err == nil {
		value := make(map[string]string)
		if err := s.Decode(COOKIE_NAME, cookie.Value, &value); err == nil {
			jsonString = "{logged_in: true}"
		}
	} else {
		jsonString = "{logged_in: false}"
	}

	// If no callback specified in URL return JSON else return JS and add callbackName
	if callbackName == "" {
		w.Header().Set("Content-Type", "application/json")
		buffer.WriteString(jsonString)
	} else {
		w.Header().Set("Content-Type", "application/javascript")
		buffer.WriteString(string(callbackName))
		buffer.WriteString(string("("))
		buffer.WriteString(jsonString)
		buffer.WriteString(")")
	}

	response = buffer.String()
	fmt.Printf("isLoggedInHandler response: %v\n", response)
	fmt.Fprintf(w, response)
}

func testPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "testPage")
}

func main() {
	//OAuth
	http.HandleFunc("/auth/google/", oauthRedirect)
	http.HandleFunc("/auth/google/callback", oauthCallbackHandler)

	//Pages
	http.HandleFunc("/", testPageHandler)
	http.HandleFunc("/isLoggedIn", isLoggedInHandler)

	http.ListenAndServe(":8000", nil)
}
