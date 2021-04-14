package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	es "github.com/3ventic/eventsubber"
	"github.com/3ventic/eventsubber/models"
	"github.com/pkg/errors"
)

const allowedHost = "eb.hel.3v.fi"

type h struct {
	Es es.Client
}

func (s *h) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("parsing body from %s: %v", req.UserAgent(), err)
		return
	}
	log.Printf("got request from %s: %s", req.UserAgent(), string(b))

	if !s.Es.VerifySignature(req.Header.Get("Twitch-Eventsub-Message-Id"), req.Header.Get("Twitch-Eventsub-Message-Timestamp"), string(b), req.Header.Get("Twitch-Eventsub-Message-Signature")) {
		res.WriteHeader(401)
		log.Print("unauthorized")
		return
	}

	switch req.Header.Get("Twitch-Eventsub-Message-Type") {
	case "webhook_callback_verification":
		verification := &models.SubscriptionChallenge{}
		err = json.Unmarshal(b, verification)
		if err != nil {
			log.Print(errors.Wrapf(err, "parsing subscription challenge: %s", string(b)))
			res.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = res.Write([]byte(verification.Challenge))
	case "notification":
		switch req.Header.Get("Twitch-Eventsub-Subscription-Type") {
		case "channel.follow":
			payload := &models.FollowEventRequest{}
			err = json.Unmarshal(b, payload)
			if err != nil {
				log.Print(err)
			}

			log.Printf("new follow %s (%s) => %s (%s)", payload.Event.UserDisplayName, payload.Event.UserId, payload.Event.BroadcasterDisplayName, payload.Event.BroadcasterId)
		}
		res.WriteHeader(http.StatusNoContent)
	default:
		_, err = res.Write([]byte("Hello there"))
	}
	if err != nil {
		log.Print(err)
	}
}

func makeHTTPServer(client es.Client) *http.Server {
	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
		Handler: &h{
			Es: client,
		},
	}
}

func main() {
	ctx := context.Background()

	client, err := es.New(ctx, &es.Options{
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		ClientID:     os.Getenv("CLIENT_ID"),
		Secret:       os.Getenv("PAYLOAD_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}

	httpServer := makeHTTPServer(client)
	httpServer.Addr = ":8137"

	exit := make(chan bool)
	go func() {
		err := httpServer.ListenAndServe()
		if err != nil {
			log.Fatal("ListenAndServe:", err)
		}
		exit <- true
		close(exit)
	}()

	sub, err := client.Subscribe(ctx, &models.SubscriptionRequest{
		Type:    "channel.follow",
		Version: "1",
		Condition: map[string]string{
			"broadcaster_user_id": "116228390", // tommyinnit
		},
		Transport: &models.Transport{
			Callback: fmt.Sprintf("https://%s/eventsub/subscriptions", allowedHost),
			Method:   models.MethodWebhook,
			Secret:   os.Getenv("PAYLOAD_SECRET"),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	if sub != nil {
		log.Printf("%+v | %+v", sub, sub.Transport)
	}
	log.Println("waiting")

	<-exit
}
