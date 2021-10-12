package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHub
var confGitHub = &oauth2.Config{
	ClientID:     "xxx",
	ClientSecret: "xxx",
	Endpoint:     github.Endpoint,
	RedirectURL:  "http://localhost:3000/login/github/callback",
	Scopes:       []string{},
}

// EOEPCA
var confEoepca = &oauth2.Config{
	ClientID:     "xxx",
	ClientSecret: "xxx",
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://test.demo.eoepca.org/oxauth/restv1/authorize",
		TokenURL: "https://test.demo.eoepca.org/oxauth/restv1/token",
	},
	RedirectURL: "http://localhost:3000/login/eoepca/callback",
	Scopes:      []string{"openid", "user_name", "is_operator"},
}

func main() {
	// Simply returns a link to the login route
	http.HandleFunc("/", rootHandler)

	// Login GitHub
	http.HandleFunc("/login/github/", createLoginHandler(confGitHub))

	// Login EOEPCA
	http.HandleFunc("/login/eoepca/", createLoginHandler(confEoepca))

	// Github callback
	http.HandleFunc("/login/github/callback", createCallbackHandler(confGitHub))

	// EOEPCA callback
	http.HandleFunc("/login/eoepca/callback", createCallbackHandler(confEoepca))

	// Route where the authenticated user is redirected to
	http.HandleFunc("/loggedin", func(w http.ResponseWriter, r *http.Request) {
		loggedinHandler(w, r)
	})

	fmt.Println("[ UP ON PORT 3000 ]")
	log.Panic(
		http.ListenAndServe(":3000", nil),
	)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, `
		<div>
			<a href="/login/github/">LOGIN GITHUB</a>
		</div>`)
	fmt.Fprintln(w, `
		<div>
			<a href="/login/eoepca/">LOGIN EOEPCA</a>
		</div>`)
}

func createLoginHandler(conf *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Redirect user to consent page to ask for permission
		// for the scopes specified above.
		redirectURL := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		fmt.Printf("Visit the URL for the auth dialog: %v\n", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

func createCallbackHandler(conf *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")

		tok, err := conf.Exchange(r.Context(), code)
		if err != nil {
			log.Fatal(err)
		}

		// Set token in a cookie (json representation has to be encoded)
		tokData, err := json.Marshal(tok)
		if err != nil {
			log.Fatal(err)
		}
		tokEncodedStr := url.QueryEscape(string(tokData))
		http.SetCookie(w, &http.Cookie{Name: "tok", Value: tokEncodedStr, Path: "/"})

		http.Redirect(w, r, "/loggedin", http.StatusFound)
	}
}

func loggedinHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	var tokPretty bytes.Buffer
	{
		var tokCookie *http.Cookie
		if tokCookie, err = r.Cookie("tok"); err == nil {
			var tokStr string
			if tokStr, err = url.QueryUnescape(tokCookie.Value); err == nil {
				err = json.Indent(&tokPretty, []byte(tokStr), "", "\t")
			}
		}
	}

	if err != nil {
		fmt.Fprintf(w, "UNAUTHORIZED")
		return
	}

	fmt.Fprintln(w, tokPretty.String())
}
