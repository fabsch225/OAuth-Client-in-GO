package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"net/url"
	"strings"
)

// NewLoginStateStore erstellt einen neuen LoginStateStore mit einer gegebenen TTL (time-to-live).
func NewLoginStateStore(ttl time.Duration) *LoginStateStore {
    return &LoginStateStore{
        states: make(map[string]LoginState),
        ttl:    ttl,
    }
}

/* 
AddState fügt einen neuen Zustand (state) mit einem Code-Verifier in den Store hinzu.
Diese Methode wird verwendet, um OAuth2-Zustände während des Login-Prozesses zu speichern.
*/
func (s *LoginStateStore) AddState(state string, codeVerifier string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.states[state] = LoginState {
		CreatedAt:    time.Now(),
		CodeVerifier: codeVerifier,
	}
}

/* 
Retrieve entfernt einen Zustand (state) aus dem Store und gibt den zugehörigen Code-Verifier zurück.
Diese Methode wird verwendet, um den Code-Verifier nach Abschluss des OAuth2-Authentifizierungsprozesses abzurufen.
*/
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

/* 
Contains überprüft, ob ein Zustand (state) im Store existiert und nicht abgelaufen ist.
Diese Methode wird verwendet, um sicherzustellen, dass ein Zustand während des OAuth2-Authentifizierungsprozesses gültig ist.
*/
func (s *LoginStateStore) Contains(state string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    loginState, exists := s.states[state]
    if !exists {
        return false
    }
    if time.Since(loginState.CreatedAt) > s.ttl {
        // Entfernt abgelaufene Zustände
        s.mu.RUnlock()
        s.mu.Lock()
        delete(s.states, state)
        s.mu.Unlock()
        s.mu.RLock()
        return false
    }
    return true
}

/* 
CleanUp entfernt abgelaufene Zustände aus dem Store.
Diese Methode wird regelmäßig aufgerufen, um sicherzustellen, dass der Store nur gültige Zustände enthält.
*/
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

/* 
handleLogin behandelt den OAuth2-Login-Prozess.
Es generiert einen Code-Verifier und einen State, speichert diesen im LoginStateStore, 
und leitet den Benutzer zur OAuth2-Authorisierungs-URL weiter.

Konkret wird "Proof Key for Code Exchange" (PKCE) nach https://datatracker.ietf.org/doc/html/rfc7636#section-4
imlpementiert. Da es sich nicht um einen Öffentlichen Client handelt ist das nach OAuth nicht notwendig,
wird aber von Authentik verlangt.

Um CSRF Angriffe zu verhindern, wird nach https://datatracker.ietf.org/doc/html/rfc6749#section-10.12 ein state Parameter
mitgeliefert. Später Authentifiziert sich der Browser Ebenfalls einem Session-Cookie und CSRF-Token der in das
Formular eingebettet ist. Das hat aber nichts mit dem hier zu tun.
*/
func handleLogin(w http.ResponseWriter, r *http.Request) {
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)
	state := generateState()
	LoginStates.AddState(state, codeVerifier)
	params := url.Values{}
	params.Add("client_id", ClientId)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")
	params.Add("redirect_uri", RedirectUrl)
	params.Add("response_type", "code")

	// Der notes Scope wird in den Access Token eingebettet: In Authentik ist eine "Resource-Id" 
	// festgelegt: Im JWT sieht das so aus: "notes": "<Id>". Der Resource Server verifiziert das dann
	// "offline_access" bedeutet, das Authentik einen refresh Token mitsendet

	params.Add("scope", "notes offline_access")
	params.Add("state", state)

	authUrlWithParams := AuthUrl + "?" + params.Encode()
	http.Redirect(w, r, authUrlWithParams, http.StatusTemporaryRedirect)
}

/* 
handleCallback behandelt den Rückruf von der OAuth2-Authentifizierungs-URL.
Es überprüft den Zustand, fordert ein Token vom Token-Endpunkt an, und speichert das Token in einer Sitzung.
*/
func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if !LoginStates.Contains(state) {
		log.Printf("invalid oauth state: '%s'", state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	codeVerifier := LoginStates.Retrieve(state)

	code := r.FormValue("code")

	// Nutzt den Authorization Code um einen Access Token abzufragen
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("redirect_uri", RedirectUrl)
	params.Add("client_id", ClientId)
	params.Add("client_secret", ClientSecret)
	params.Add("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", TokenUrl, strings.NewReader(params.Encode()))
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := Client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	// Liest und verarbeitet die Antwort
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error: %s\n", body)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	// Parse die JSON-Antwort
	var tokenResponse OAuthToken
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		log.Printf("Error parsing response: %v\n", err)
		return
	}

	sessionToken, _ := Sessions.AddToken(tokenResponse)
	
	http.SetCookie(w, &http.Cookie{
        Name:     "GoNotesSessionToken",
        Value:    sessionToken,
        Path:     "/",
        Domain:   "37.27.87.77",
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
        Secure:   true,
    })

	http.Redirect(w, r, ApplicationUrl, http.StatusFound)
}
