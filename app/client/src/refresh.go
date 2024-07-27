package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
	"log"
)

func refreshAccessTokenIfPossible(sessionData *SessionTokenData) error {
	if time.Now().After(sessionData.AccessTokenExpiresAt) {
		log.Println("Trying to use a Refresh Token")
		newToken, err := consumeRefreshToken(sessionData.Token.RefreshToken)
		if err != nil {
			return err
		}
		sessionData.Token = *newToken
		sessionData.AccessTokenExpiresAt = time.Now().Add(250 * time.Second)
		log.Println("Refresh Succsesful")
	}
	return nil
}

func consumeRefreshToken(refreshToken string) (*OAuthToken, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", ClientId)
	data.Set("client_secret", ClientSecret)
	data.Set("redirect_uri", RedirectUrl)

	req, err := http.NewRequest("POST", TokenUrl, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("bad response status: %s, body: %s", resp.Status, string(bodyBytes))
	}

	var tokenResp OAuthToken
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, fmt.Errorf("decoding response: %v", err)
	}

	return &tokenResp, nil
}