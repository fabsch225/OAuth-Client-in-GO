package main

import (
	"time"
	"sync"
)

type AuthParams struct {
	AuthUrl             string
	ClientId            string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectUri         string
	ResponseType        string
	Scope               string
	State               string
}

const AuthCodeUrlTemplate = `{{.AuthUrl}}?client_id={{.ClientId}}&code_challenge={{.CodeChallenge}}&code_challenge_method={{.CodeChallengeMethod}}&redirect_uri={{.RedirectUri}}&response_type={{.ResponseType}}&scope={{.Scope}}&state={{.State}}`

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
}

type CSRFToken struct {
	Source string
}

type SessionTokenData struct {
	Token            OAuthToken
	CSRFToken		 CSRFToken
	SessionExpiresAt time.Time
}

type SessionTokenStore struct {
	tokens map[string]SessionTokenData
	mu     sync.RWMutex
	ttl    time.Duration
}

func NewSessionTokenStore() *SessionTokenStore {
	//ttl is left 0 -> there is 0 tolerance for late sessions
    return &SessionTokenStore{
        tokens: make(map[string]SessionTokenData),
    }
}

type LoginState struct {
	CodeVerifier string
	CreatedAt    time.Time
}

//set of state-strings with a time stamp
type LoginStateStore struct {
    states map[string]LoginState
    mu     sync.RWMutex
	ttl    time.Duration
}

func NewLoginStateStore(ttl time.Duration) *LoginStateStore {
    return &LoginStateStore{
        states: make(map[string]LoginState),
        ttl:    ttl,
    }
}

type ExchangeParams struct {
	Code         string
	CodeVerifier string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

const ExchangeBodyTemplate = `grant_type=authorization_code&code={{.Code}}&redirect_uri={{.RedirectURI}}&client_id={{.ClientID}}&client_secret={{.ClientSecret}}&code_verifier={{.CodeVerifier}}`
