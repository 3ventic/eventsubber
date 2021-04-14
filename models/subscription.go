package models

import "time"

type Subscription struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Type      string            `json:"type"`
	Version   string            `json:"version"`
	Condition map[string]string `json:"condition"`
	Transport *Transport        `json:"transport"`
	CreatedAt time.Time         `json:"created_at"`
}
