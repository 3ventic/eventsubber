package models

type SubscriptionChallenge struct {
	Challenge    string        `json:"challenge"`
	Subscription *Subscription `json:"subscription"`
}
