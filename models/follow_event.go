package models

type FollowEvent struct {
	UserId                 string `json:"user_id"`
	UserLogin              string `json:"user_login"`
	UserDisplayName        string `json:"user_name"`
	BroadcasterId          string `json:"broadcaster_id"`
	BroadcasterLogin       string `json:"broadcaster_login"`
	BroadcasterDisplayName string `json:"broadcaster_name"`
}

type FollowEventRequest struct {
	Subscription Subscription `json:"subscription"`
	Event        FollowEvent  `json:"event"`
}
