package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// TokenInfo represents the structure of the introspection response
type TokenInfo struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	Username  string `json:"username"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	Sub       string `json:"sub"`
}

// IntrospectToken introspects the provided token using the Authentik introspection endpoint
func IntrospectToken(token string) (*TokenInfo, error) {
	// Prepare the form data
	form := url.Values{}
	form.Set("token", token)

	// Create the request
	req, err := http.NewRequest("POST", IntrospectionUrl, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}

	// Set the request headers
	req.SetBasicAuth(ClientId, ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Perform the request
	resp, err := Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to introspect token: %d", resp.StatusCode)
	}

	// Decode the JSON response
	var tokenInfo TokenInfo
	err = json.NewDecoder(resp.Body).Decode(&tokenInfo)
	if err != nil {
		return nil, err
	}

	return &tokenInfo, nil
}