package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/calendar/v3"
)

const calendarID = "primary"

var config *oauth2.Config

func initializeCalendarConfig() {
	b, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err = google.ConfigFromJSON(b, calendar.CalendarEventsScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
}

// createEvent creates a new event for the user authenticated with the given token
func createEvent(tok *oauth2.Token) (*calendar.Event, error) {
	client := config.Client(context.Background(), tok)

	srv, err := calendar.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Calendar client: %v", err)
	}

	now := time.Now()

	event := &calendar.Event{
		Summary:     "Slack-Generated Google Meet Event",
		Description: "Auto-generated meeting to facilitate easy Google Meet meeting creation.",
		Start: &calendar.EventDateTime{
			DateTime: now.Format(time.RFC3339),
		},
		End: &calendar.EventDateTime{
			DateTime: now.Add(time.Minute * 30).Format(time.RFC3339),
		},
		ConferenceData: &calendar.ConferenceData{
			CreateRequest: &calendar.CreateConferenceRequest{
				RequestId: uuid.New().String(),
			},
		},
	}

	event, err = srv.Events.Insert(calendarID, event).ConferenceDataVersion(1).Do()
	if err != nil {
		log.Fatalf("Unable insert event: %v", err)
	}
	jsonOutput, err := event.MarshalJSON()
	if err != nil {
		log.Fatalf("Unable to conver to json: %v", err)
	}
	fmt.Println("Created event Google meet link:", string(jsonOutput))

	// Confirm that createRequest was a success
	if event.ConferenceData.CreateRequest.Status.StatusCode == "success" {
		return event, nil
	}

	return nil, fmt.Errorf("Failed to create conference")
}
