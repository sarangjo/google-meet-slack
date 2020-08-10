# google-meet-slack

Slack bot to create Google Meet links instantaneously

## Workflow

1. Slack app is installed in the workspace
2. User types `/gmeet` command
3. Server checks if we have a Google Calendar authentication token for this Slack user. If not, go down below
4. Use the gcal oauth token to perform the event creation, get Meet link, delete event (maybe), and respond with that data

## Db

Stores links from slack user ID to google auth token
