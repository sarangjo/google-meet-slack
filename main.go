package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/gorilla/sessions"
	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

var (
	signingSecret string
	port          string
	tmpl          *template.Template
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

type templateData struct {
	Hello             string
	SlackUserID       string
	SlackTeamID       string
	GoogleAccessToken string
}

const cookieName = "cookie-name"

const (
	sessionActive  = "active"
	sessionUserID  = "userID"
	sessionTeamID  = "teamID"
	sessionToken   = "accessToken"
	sessionRefresh = "refreshToken"
	sessionExpiry  = "expiry"
)

// TODO session expiry?
func authHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	session.Values[sessionActive] = true
	slackUserID, ok := session.Values[sessionUserID].(string)
	if !ok {
		slackUserID = ""
	}
	slackTeamID, ok := session.Values[sessionTeamID].(string)
	if !ok {
		slackTeamID = ""
	}
	googleAccessToken, ok := session.Values[sessionToken].(string)
	if !ok {
		googleAccessToken = "" // oauth2.Token{}
	}

	data := templateData{
		Hello:             "lulmaozedong",
		SlackUserID:       slackUserID,
		SlackTeamID:       slackTeamID,
		GoogleAccessToken: googleAccessToken,
	}

	session.Save(r, w)

	err = tmpl.Execute(w, data)
	if err != nil {
		fmt.Println("Unable to execute template", err)
	}
}

func connectHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	auth, ok := session.Values[sessionActive].(bool)
	fmt.Println("auth", auth, "ok", ok)
	if !auth || !ok {
		fmt.Println("Hasn't set active to true")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	fmt.Println("Method", r.Method, "URL", r.URL.Query().Encode())

	slackUserID, _ := session.Values[sessionUserID].(string)
	slackTeamID, _ := session.Values[sessionTeamID].(string)
	googleAccessToken, _ := session.Values[sessionToken].(string)
	if slackUserID == "" || slackTeamID == "" || googleAccessToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Session variables not set. go to /auth"))
		return
	}
	refreshToken, _ := session.Values[sessionRefresh].(string)
	expiry, _ := session.Values[sessionExpiry].(time.Time)

	// Persist to db
	tok := Token{
		TeamID: slackTeamID,
		UserID: slackUserID,
		OAuthToken: oauth2.Token{
			AccessToken:  googleAccessToken,
			RefreshToken: refreshToken,
			Expiry:       expiry,
		},
	}
	err = saveToken(&tok)
	if err != nil {
		fmt.Println("unable to persist and save connection")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully connected! You can now run /gmeet in Slack"))
}

func slackRedirectHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	auth, ok := session.Values[sessionActive].(bool)
	fmt.Println("auth", auth, "ok", ok)
	if !auth || !ok {
		fmt.Println("Hasn't set active to true")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	fmt.Println("Method", r.Method, "URL", r.URL.Query().Encode())

	code := r.URL.Query().Get("code")
	if code == "" {
		fmt.Println("No code param")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No code param provided"))
		return
	}

	// Get slack auth information
	clientID := "654762687334.1130021352737"
	clientSecret := "3d6e8dcd6658845f56cac08152db93ea"

	httpClient := &http.Client{}

	resp, err := slack.GetOAuthV2Response(httpClient, clientID, clientSecret, code, "")
	if err != nil || !resp.Ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Unable to get user information"))
		return
	}

	fmt.Println("user id", resp.AuthedUser.ID, "team id", resp.Team.ID, "team name", resp.Team.Name)

	session.Values[sessionUserID] = resp.AuthedUser.ID
	session.Values[sessionTeamID] = resp.Team.ID
	session.Save(r, w)

	http.Redirect(w, r, "/auth", http.StatusTemporaryRedirect)
}

func googleRedirectHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	auth, ok := session.Values[sessionActive].(bool)
	fmt.Println("auth", auth, "ok", ok)
	if !auth || !ok {
		fmt.Println("Hasn't set active to true")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	fmt.Println("Method", r.Method, "URL", r.URL.Query().Encode())

	code := r.URL.Query().Get("code")
	if code == "" {
		fmt.Println("No code param")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No code param provided"))
		return
	}

	resp, err := http.PostForm("https://oauth2.googleapis.com/token",
		url.Values{
			"code":          {code},
			"client_id":     {"1035206939710-u3chvhivekhhi3v7qbcuddu4ktd8paou.apps.googleusercontent.com"},
			"client_secret": {"NLNmqGT07m8rkSmtwp8XKo6y"},
			"redirect_uri":  {"http://localhost:5555/googleRedirect"},
			"grant_type":    {"authorization_code"},
		},
	)
	if err != nil {
		fmt.Println("unable to get oauth token")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("unable to read body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var token oauth2.Token
	err = json.Unmarshal(body, &token)
	if err != nil {
		fmt.Println("unable to unmarshal json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Println("access token", token.AccessToken)

	session.Values[sessionToken] = token.AccessToken
	session.Values[sessionRefresh] = token.RefreshToken
	session.Values[sessionExpiry] = token.Expiry
	session.Save(r, w)

	http.Redirect(w, r, "/auth", http.StatusTemporaryRedirect)
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

	// Auth endpoints
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/slackRedirect", slackRedirectHandler)
	http.HandleFunc("/googleRedirect", googleRedirectHandler)
	http.HandleFunc("/connect", connectHandler)
	// Slash command handler
	http.HandleFunc("/new", getLinkHandler)
	// Catch-all
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hey I love %s!", r.URL.Path[1:])
	})
	http.ListenAndServe(":"+port, nil)
}
