package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"
)
// AddState adds a new state to the store with a timestamp.
func (s *LoginStateStore) AddState(state string, codeVerifier string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.states[state] = LoginState {
		CreatedAt:    time.Now(),
		CodeVerifier: codeVerifier,
	}
}

// Retrieve removes a state from the store.
func (s *LoginStateStore) Retrieve(state string) string {
    s.mu.Lock()
    defer s.mu.Unlock()
	loginState, exists := s.states[state]
	var codeVerifier string
    if exists {
        codeVerifier = loginState.CodeVerifier
    }
    delete(s.states, state)
	return codeVerifier
}

// Contains checks if the state is in the store and has not expired.
func (s *LoginStateStore) Contains(state string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    loginState, exists := s.states[state]
    if !exists {
        return false
    }
    if time.Since(loginState.CreatedAt) > s.ttl {
        // Remove expired state
        s.mu.RUnlock()
        s.mu.Lock()
        delete(s.states, state)
        s.mu.Unlock()
        s.mu.RLock()
        return false
    }
    return true
}

// CleanUp removes expired states from the store.
func (s *LoginStateStore) CleanUp() {
    s.mu.Lock()
    defer s.mu.Unlock()
    now := time.Now()
    for state, loginState := range s.states {
        if now.Sub(loginState.CreatedAt) > s.ttl {
            delete(s.states, state)
        }
    }
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)
	state := generateState()
	LoginStates.AddState(state, codeVerifier)
	params := AuthParams{
		AuthUrl:             AuthURL,
		ClientId:            ClientId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		RedirectUri:         RedirectUrl,
		ResponseType:        "code",
		Scope:               "notes offline_access",
		State:               state,
	}
	url2, _ := generateAuthURL(params)
	fmt.Println(state)
	fmt.Println(url2)
	http.Redirect(w, r, url2, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if !LoginStates.Contains(state) {
		log.Printf("invalid oauth state: '%s'", state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	codeVerifier := LoginStates.Retrieve(state)

	code := r.FormValue("code")

	params := ExchangeParams{
		ClientSecret: ClientSecret,
		ClientID:     ClientId,
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  RedirectUrl,
	}

	tmpl, err := template.New("ExchangeUrl").Parse(ExchangeBodyTemplate)
	if err != nil {
		log.Printf("Error parsing template: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var ExchangeUrlBody bytes.Buffer
	if err := tmpl.Execute(&ExchangeUrlBody, params); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing template: %v\n", err)
		return
	}
	req, err := http.NewRequest("POST", TokenURL, &ExchangeUrlBody)
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		return
	}

	// Set the appropriate headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Read and process the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error: %s\n", body)
		return
	}

	// Parse the JSON response
	var tokenResponse OAuthToken
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		return
	}

	//test the token
	fmt.Println(tokenResponse)
	req, _ = http.NewRequest("GET", UserInfoUrl, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("failed getting user info: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	//Todo Remove this Part
	//Test Refresh Token Logic
	/*newToken, err := consumeRefreshToken(tokenResponse.RefreshToken)
	if (err != nil) {
		fmt.Println(tokenResponse)
		fmt.Println(err)
	}
	tokenResponse = *newToken*/

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	newStr := buf.String()

	fmt.Fprintf(w, "{\"Content\": %s\n, \"Token\": %s\n}", newStr, string(body))
}