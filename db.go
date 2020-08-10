package main

import (
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// Token will have:
// - teamId - slack team ID
// - userId - slack user ID
// - enterpriseId? - TODO
// - token - Google oauth access token
type Token struct {
	TeamID     string       `json:"teamId"`
	UserID     string       `json:"userId"`
	OAuthToken oauth2.Token `json:"token"`
}

// Global state
var client *mongo.Client
var db *mongo.Database

func initializeDbClient() {
	// TODO password
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		fmt.Println("Unable to connect", err)
		os.Exit(1)
	}

	db = client.Database("gmeet")
}

const tokenCollection = "tokens"

// lookupToken finds a token identified by user id and team id
func lookupToken(userID string, teamID string, token *Token) error {
	tokens := db.Collection(tokenCollection)
	return tokens.FindOne(context.Background(), bson.M{"teamId": teamID, "userId": userID}).Decode(token)
}
