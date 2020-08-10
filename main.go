package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

var (
	signingSecret string
	port          string
	tmpl          *template.Template
)

func authHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.Execute(w, nil)
}

const shouldVerify = false

// Handler for the actual `/gmeet` command from Slack
func getLinkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var s slack.SlashCommand
	var err error
	if shouldVerify {
		// Create secret verifier
		var verifier slack.SecretsVerifier
		verifier, err = slack.NewSecretsVerifier(r.Header, signingSecret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Parse slash command body
		r.Body = ioutil.NopCloser(io.TeeReader(r.Body, &verifier))
		s, err = slack.SlashCommandParse(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify secret in the payload
		if err = verifier.Ensure(); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else {
		s, err = slack.SlashCommandParse(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// Execute command
	switch s.Command {
	case "/gmeet":
		// 1. Authenticate the requesting user.
		if s.TeamID == "" || s.UserID == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var fullToken Token
		err := lookupToken(s.UserID, s.TeamID, &fullToken)
		if err != nil {
			b := []byte("Couldn't find token")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(b)
			return
		}

		var tok *oauth2.Token

		// 2. Pass OAuth2 token into event creator as tok
		event, err := createEvent(tok)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// 3. Return event information back to Slack
		entryPoints := event.ConferenceData.EntryPoints
		var (
			meetLink  string
			meetPhone string
			meetPIN   string
		)
		for _, ep := range entryPoints {
			if ep.EntryPointType == "video" {
				meetLink = ep.Uri
			} else if ep.EntryPointType == "phone" {
				meetPhone = ep.Uri
				meetPIN = ep.Pin
			}
		}

		params := &slack.Msg{
			Text: fmt.Sprintf("Meet link: %v, Phone: %v PIN %v", meetLink, meetPhone, meetPIN),
		}
		b, err := json.Marshal(params)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	default:
		b := []byte("Invalid slash command")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(b)
		return
	}
}

func main() {
	signingSecret = os.Getenv("SLACK_SIGNING_SECRET")
	port = os.Getenv("PORT")

	if port == "" || signingSecret == "" {
		log.Println("$PORT and $SLACK_SIGNING_SECRET not set; defaulting")
		port = "5555"
		secretBytes, err := ioutil.ReadFile("slack-signing.txt")
		if err != nil {
			log.Fatalln("Can't find default signing secret")
		}
		signingSecret = strings.TrimSpace(string(secretBytes))
	}

	tmpl = template.Must(template.ParseFiles("auth.html"))

	// initialize our global state
	initializeDbClient()
	initializeCalendarConfig()

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/new", getLinkHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hey I love %s!", r.URL.Path[1:])
	})
	http.ListenAndServe(":"+port, nil)
}
