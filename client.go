package es

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/3ventic/eventsubber/models"
	"github.com/pkg/errors"
)

type Client interface {
	Subscribe(ctx context.Context, sub *models.SubscriptionRequest) (*models.Subscription, error)
	Subscriptions(ctx context.Context) ([]*models.Subscription, error)
	VerifySignature(messageId, timestamp, body, signature string) bool
	Unsubscribe(ctx context.Context, id string) error
}

type Options struct {
	HttpClient   *http.Client
	ClientID     string
	ClientSecret string
	Secret       string
}

func New(ctx context.Context, options *Options) (Client, error) {
	hc := http.DefaultClient
	if options.HttpClient != nil {
		hc = options.HttpClient
	}

	if options.ClientID == "" || options.ClientSecret == "" {
		return nil, errors.New("clientid and token required")
	}

	c := &client{
		hc:           hc,
		clientID:     options.ClientID,
		clientSecret: options.ClientSecret,
		secret:       options.Secret,
	}

	err := c.refreshToken(ctx)
	return c, errors.Wrap(err, "creating client")
}

const (
	headerClientID      = "client-id"
	headerAuthorization = "authorization"
	headerUserAgent     = "user-agent"
	headerContentType   = "content-type"
)

type client struct {
	hc           *http.Client
	clientID     string
	clientSecret string
	token        string
	secret       string
}

func (c *client) VerifySignature(messageId, timestamp, body, signature string) bool {
	hmacMessage := messageId + timestamp + body

	signatureParts := strings.Split(signature, "=")
	algo := signatureParts[0]
	givenHash := signatureParts[1]

	hasher := func() hash.Hash {
		switch algo {
		case "sha256":
			return sha256.New()
		default:
			return sha256.New()
		}
	}

	h := hmac.New(hasher, []byte(c.secret))
	h.Write([]byte(hmacMessage))

	calculatedHash := hex.EncodeToString(h.Sum(nil))

	return givenHash == calculatedHash
}

func (c *client) Subscriptions(ctx context.Context) ([]*models.Subscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twitch.tv/helix/eventsub/subscriptions", nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}
	c.setHeaders(req)

	res, b, err := c.doWithTokenRetry(ctx, req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status %d: %s", res.StatusCode, string(b))
	}

	result := &models.SubscriptionResponse{}
	err = json.Unmarshal(b, result)
	if err != nil {
		return nil, errors.Wrap(err, "parsing response")
	}

	return result.Data, nil
}

func (c *client) Subscribe(ctx context.Context, sub *models.SubscriptionRequest) (*models.Subscription, error) {
	payloadBuf, err := json.Marshal(sub)
	if err != nil {
		return nil, errors.Wrap(err, "encoding request")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitch.tv/helix/eventsub/subscriptions", strings.NewReader(string(payloadBuf)))
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}
	c.setHeaders(req)

	res, b, err := c.doWithTokenRetry(ctx, req)
	if err != nil {
		return nil, err
	}

	switch res.StatusCode {
	case http.StatusConflict:
		return nil, nil
	}

	if res.StatusCode != http.StatusAccepted {
		return nil, errors.Errorf("unexpected status %d: %s", res.StatusCode, string(b))
	}

	result := &models.SubscriptionResponse{}
	err = json.Unmarshal(b, result)
	if err != nil {
		return nil, errors.Wrap(err, "parsing response")
	}

	if len(result.Data) != 1 {
		return nil, errors.Errorf("unexpected number of responses %d", len(result.Data))
	}

	return result.Data[0], nil
}

func (c *client) Unsubscribe(ctx context.Context, id string) error {
	data := url.Values{}
	data.Set("id", id)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "https://api.twitch.tv/helix/eventsub/subscriptions?"+data.Encode(), nil)
	if err != nil {
		return errors.Wrap(err, "creating request")
	}

	res, _, err := c.doWithTokenRetry(ctx, req)
	if err != nil {
		return err
	}

	switch res.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	default:
		return errors.Errorf("unexpected status %d", res.StatusCode)
	}
}

func (c *client) setHeaders(req *http.Request) {
	req.Header.Add(headerClientID, c.clientID)
	req.Header.Add(headerAuthorization, fmt.Sprintf("Bearer %s", c.token))
	req.Header.Add(headerUserAgent, "eventsubber")
	req.Header.Add(headerContentType, "application/json")
}

func (c *client) doWithTokenRetry(ctx context.Context, req *http.Request) (res *http.Response, body []byte, err error) {
	res, err = c.hc.Do(req)
	if err != nil {
		err = errors.Wrap(err, "making request")
		return
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized {
		err = c.refreshToken(ctx)
		if err != nil {
			err = errors.Wrap(err, "refreshing token")
			return
		}
		res, err = c.hc.Do(req)
		if err != nil {
			err = errors.Wrap(err, "making request")
			return
		}
		defer res.Body.Close()
	}

	body, err = io.ReadAll(res.Body)
	if err != nil {
		err = errors.Wrap(err, "reading response")
		return
	}

	return
}

func (c *client) refreshToken(ctx context.Context) error {
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://id.twitch.tv/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return errors.Wrap(err, "creating request")
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("content-length", strconv.Itoa(len(data.Encode())))

	res, err := c.hc.Do(req)
	if err != nil {
		return errors.Wrap(err, "making request")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.Errorf("unexpected status %d fetching token", res.StatusCode)
	}

	result := &models.AuthenticationResponse{}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "reading response")
	}

	err = json.Unmarshal(b, result)
	if err != nil {
		return errors.Wrap(err, "parsing response")
	}

	c.token = result.AccessToken

	return nil
}
