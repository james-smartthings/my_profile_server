package main

import (
	// Standard library packages
	"fmt"
	"net/http"
	"time"
	"os"
	"bytes"
	"strings"
	"net/url"

	// Third party packages
	"github.com/pborman/uuid"
	"golang.org/x/oauth2"
	// "golang.org/x/oauth2/google"
	"github.com/gorilla/securecookie"
)

// Globals
const COOKIE_NAME = "st_uuid"
const CLIENT_ID = "ec41d30d-18f6-497c-bdd8-c239fc99ba18"
const CLIENT_SECRET = "bddb8c1c-28a2-4820-9def-33480eb1c2ad"
const DEV_PROFILE_CLIENT_URL = "http://localhost:3000"

var cookieJar map[string]*oauth2.Token
var hashKey = []byte( os.Getenv("DEV_PROFILE_CLIENT_HASH_KEY") )
var blockKey = []byte( os.Getenv("DEV_PROFILE_CLIENT_BLOCK_KEY") )
var s = securecookie.New(hashKey, blockKey)

// Your credentials should be obtained from the Google
// Developer Console (https://console.developers.google.com).
var oauthCfg = &oauth2.Config{
	// ClientID: "ec41d30d-18f6-497c-bdd8-c239fc99ba18",
	// ClientSecret: "bddb8c1c-28a2-4820-9def-33480eb1c2ad",
	ClientID: CLIENT_ID,
	ClientSecret: CLIENT_SECRET,
	RedirectURL:  "http://localhost:8000/auth/callback",
	Scopes: []string{"app"},
	Endpoint: oauth2.Endpoint{
		AuthURL: "https://auth-globald.smartthingsgdev.com/oauth/authorize",
		TokenURL: "https://auth-globald.smartthingsgdev.com/oauth/token",
	},
}

// Handlers
func oauthRedirect(w http.ResponseWriter, r *http.Request) {
	form := url.Values{}
	form.Add("response_type", "token")
	form.Add("client_id", CLIENT_ID)
	form.Add("client_secret", CLIENT_SECRET)
	form.Add("scope", "service")
	// form.Add("redirect_uri", "http://localhost:8000/auth/callback")
	params  := form.Encode()

	var buffer bytes.Buffer
	buffer.WriteString("https://auth-globald.smartthingsgdev.com/oauth/authorize")
	buffer.WriteString("?")
	buffer.WriteString(params)

	reqURL := buffer.String()

	http.Redirect(w,r, reqURL, http.StatusTemporaryRedirect)
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("CALLBACK\n")

	code := r.FormValue("code")
	fmt.Printf("INITIAL REQUEST: %+v\n\n", r)
	fmt.Printf("CODE: %v\n\n", code)
	// fmt.Printf("oauth2.NoContext: %v\n", oauth2.NoContext)
	// fmt.Println("*************\n")
	// fmt.Printf("code: %v\n", code)
	// fmt.Println("*************\n")
	// token, err := oauthCfg.Exchange(oauth2.NoContext, code)
	// fmt.Printf("TOKEN: %v\n", token)
	// fmt.Printf("Error: %v\n", err)

	client := &http.Client{}
	tokenURL := "https://auth-globald.smartthingsgdev.com/oauth/token"

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Add("code", code)
	form.Add("client_id", CLIENT_ID)
	form.Add("client_secret", CLIENT_SECRET)
	form.Add("redirect_uri", "http://localhost:8000/")

	// buffer.WriteString("code=\"")
	// buffer.WriteString(code)
	// buffer.WriteString("\"")
	// codeStr := buffer.String()

	// req, _ := http.NewRequest("POST", tokenURL, nil )
	req, _ := http.NewRequest("POST", tokenURL, bytes.NewBufferString(form.Encode()) )

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Add("Host", "auth-globald.smartthingsgdev.com")

	// req.Header.Add("Authorization", "grant_type=\"authorization_code\"")
	// req.Header.Add("Authorization", codeStr)
	// req.Header.Add("Authorization", "client_id=\"6fbeca4f-b497-4a90-9403-ef2befcda89d\"")
	// req.Header.Add("Authorization", "client_secret=\"f04c8806-d58c-4d24-bc99-bd27f03c7b3c\"")
	// req.Header.Add("Authorization", "redirect_uri=\"http://localhost:8000/auth/callback\"")

	fmt.Println("\n**********\n")
	fmt.Printf("REQUEST: %+v\n", req)
	fmt.Println("\n**********\n")

	res, err := client.Do(req)

	fmt.Printf("RESPONSE: %+v\n", res);
	fmt.Printf("ERROR: %v\n", err);

	//
	// if err != nil {
	// 	// Invalid Token
	// 	http.Redirect(w, r, "https://graph.api.smartthings.com/register/index", http.StatusTemporaryRedirect)
	// }
	// //Valid Token. Generate new cookie & save it
	// if cookieJar == nil {
	// 	cookieJar = make(map[string]*oauth2.Token)
	// }
	// buildAndSaveCookie(w,r, token)
	// http.Redirect(w, r, DEV_PROFILE_CLIENT_URL, http.StatusTemporaryRedirect)
}

func oauthSuccessCallbackHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w,r, DEV_PROFILE_CLIENT_URL, http.StatusTemporaryRedirect)
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
		} else {
			fmt.Printf("ERROR: %v\n", err)
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
	http.HandleFunc("/auth/", oauthRedirect)
	http.HandleFunc("/auth/callback", oauthCallbackHandler)
	http.HandleFunc("/auth/success", oauthSuccessCallbackHandler)
	//Pages
	http.HandleFunc("/", testPageHandler)
	http.HandleFunc("/isLoggedIn", isLoggedInHandler)

	http.ListenAndServe(":8000", nil)
}
