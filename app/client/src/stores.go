// ##############################################################################################
// Hier stehen die Datenstrukturen zur speicherung von Sessions und 
// Login-States (https://datatracker.ietf.org/doc/html/rfc6749#section-10.12),
// sowie Routine, die die Speicher periodisch aufräumen
// ##############################################################################################

package main

import (
    "time"
    "log"
    "net/url"
    "sync"
    "net/http"
    "bytes"
    "io/ioutil"
    "fmt"
    "encoding/json"
)

// zur Darstellung eines CSRF-Tokens
type CSRFToken struct {
	Source string
}

// zur Speicherung von Session-Daten, einschließlich OAuth2-Token, CSRF-Token und Ablaufzeiten für Access- und Session-Tokens.
type SessionTokenData struct {
	Token                OAuthToken
	CSRFToken		     CSRFToken
	AccessTokenExpiresAt time.Time
	SessionExpiresAt     time.Time
}

// zur Verwaltung eines Stores für Session-Tokens. Enthält eine Map zur Speicherung der Tokens, 
// einen Mutex zur Synchronisierung und eine TTL (time-to-live) für die Tokens.
type SessionTokenStore struct {
	tokens map[string]SessionTokenData
	mu     sync.RWMutex
	ttl    time.Duration
}

// AddToken fügt ein neues Access-Token zum Store hinzu.
// Es generiert einen neuen Session-Token und einen CSRF-Token.
// Der neue Eintrag wird im Store gespeichert und die Tokens werden zurückgegeben.
func (store *SessionTokenStore) AddToken(token OAuthToken) (string, string) {
    store.mu.Lock()
    defer store.mu.Unlock()
	
    sessionToken := generateSessionToken()
    csrfToken := generateCSRFTokenSource()

	entry := SessionTokenData {
		CSRFToken: 		      CSRFToken {
			                      Source: csrfToken,
						      },
		Token:                token,
        AccessTokenExpiresAt: time.Now().Add(10 * time.Second),
		SessionExpiresAt:     time.Now().Add(store.ttl),
	}
    store.tokens[sessionToken] = entry

    return sessionToken, csrfToken
}

// GetToken ruft ein Access-Token aus dem Store anhand der ID ab.
// Es wird geprüft, ob das Token existiert, und das Token sowie ein Existenz-Flag zurückgegeben.
func (store *SessionTokenStore) GetToken(id string) (*OAuthToken, bool) {
    store.mu.RLock()
    defer store.mu.RUnlock()
    entry, exists := store.tokens[id]
    return &entry.Token, exists
}

// GetData ruft alle Session-Daten aus dem Store anhand der ID ab.
// Es wird geprüft, ob die Daten existieren, und die Daten sowie ein Existenz-Flag zurückgegeben.
func (store *SessionTokenStore) GetData(id string) (*SessionTokenData, bool) {
    store.mu.RLock()
    defer store.mu.RUnlock()
    entry, exists := store.tokens[id]
    return &entry, exists
}

// RefreshAccess aktualisiert den Access-Token, falls möglich, anhand der ID.
// Es wird versucht, den Access-Token mit einem Refresh-Token zu erneuern, falls der aktuelle Token abgelaufen ist.
func (store *SessionTokenStore) RefreshAccess(id string) {
    store.mu.Lock()
    defer store.mu.Unlock()
    data := store.tokens[id]
    err := data.refreshAccessTokenIfPossible()
    if err != nil {
        log.Printf("cannot refresh Token: %s\n", err.Error)
    }
    store.tokens[id] = data
}

// RemoveToken entfernt ein Access-Token aus dem Store anhand der Session-Token-ID.
func (store *SessionTokenStore) RemoveToken(id string) {
    store.mu.Lock()
    defer store.mu.Unlock()
    delete(store.tokens, id)
}

// IsExpired prüft, ob ein bestimmter Session-Token abgelaufen ist.
// Wenn der Token nicht existiert oder das Ablaufdatum überschritten wurde, wird true zurückgegeben.
func (store *SessionTokenStore) IsExpired(id string) bool {
    store.mu.RLock()
    defer store.mu.RUnlock()
    token, exists := store.tokens[id]
    if !exists {
        return true
    }
    return time.Now().After(token.SessionExpiresAt)
}

// CleanUp entfernt abgelaufene Tokens aus dem Store.
// Es wird durch alle gespeicherten Tokens iteriert und die abgelaufenen Tokens werden gelöscht.
func (s *SessionTokenStore) CleanUp() {
    s.mu.Lock()
    defer s.mu.Unlock()
    now := time.Now()
    for token, data := range s.tokens {
        if now.Sub(data.SessionExpiresAt) > s.ttl {
            delete(s.tokens, token)
        }
    }
}

// NewSessionTokenStore erstellt eine neue Instanz von SessionTokenStore.
// Es initialisiert den Store mit einer leeren Token-Map und einem TTL von 10 Minuten.
func NewSessionTokenStore() *SessionTokenStore {
    return &SessionTokenStore{
        tokens: make(map[string]SessionTokenData),
		ttl: time.Minute * 10,
    }
}



// zur Speicherung des Login-Zustands während des OAuth2-Authentifizierungsprozesses. 
// Enthält den Code-Verifier und den Zeitpunkt der Erstellung.
type LoginState struct {
	CodeVerifier string
	CreatedAt    time.Time
}

// zur Verwaltung eines Stores für Login-Zustände. Enthält eine Map zur Speicherung der Zustände, 
// einen Mutex zur Synchronisierung und eine TTL (time-to-live) für die Zustände.
type LoginStateStore struct {
    states map[string]LoginState
    mu     sync.RWMutex
	ttl    time.Duration
}


// NewLoginStateStore erstellt einen neuen LoginStateStore mit einer gegebenen TTL (time-to-live).
func NewLoginStateStore(ttl time.Duration) *LoginStateStore {
    return &LoginStateStore{
        states: make(map[string]LoginState),
        ttl:    ttl,
    }
}


// AddState fügt einen neuen Zustand (state) mit einem Code-Verifier in den Store hinzu.
// Diese Methode wird verwendet, um OAuth2-Zustände während des Login-Prozesses zu speichern.

func (s *LoginStateStore) AddState(state string, codeVerifier string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.states[state] = LoginState {
		CreatedAt:    time.Now(),
		CodeVerifier: codeVerifier,
	}
}


// Retrieve entfernt einen Zustand (state) aus dem Store und gibt den zugehörigen Code-Verifier zurück.
// Diese Methode wird verwendet, um den Code-Verifier nach Abschluss des OAuth2-Authentifizierungsprozesses abzurufen.

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


// Contains überprüft, ob ein Zustand (state) im Store existiert und nicht abgelaufen ist.
// Diese Methode wird verwendet, um sicherzustellen, dass ein Zustand während des OAuth2-Authentifizierungsprozesses gültig ist.

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


// Diese Methode prüft, ob der aktuelle Access-Token abgelaufen ist, und versucht, diesen mit einem Refresh-Token zu erneuern.
// Wenn der Access-Token abgelaufen ist, wird die Methode 'consumeRefreshToken' aufgerufen, um einen neuen Access-Token zu erhalten.
// Wenn der Erneuerungsvorgang erfolgreich ist, werden die neuen Token-Daten aktualisiert und das Ablaufdatum des Access-Tokens neu gesetzt.
func (sessionData *SessionTokenData) refreshAccessTokenIfPossible() error {
	if time.Now().After(sessionData.AccessTokenExpiresAt) {
		log.Println("Trying to use a Refresh Token")
		newToken, err := consumeRefreshToken(sessionData.Token.RefreshToken)
		if err != nil {
			return err
		}
		sessionData.Token = *newToken
		sessionData.AccessTokenExpiresAt = time.Now().Add(250 * time.Second)
		log.Println("Refresh Successful")
	}
	return nil
}

// Diese Funktion verwendet ein Refresh-Token, um einen neuen OAuth-Access-Token zu erhalten.
// Ein POST-Request wird an den Token-Endpunkt gesendet, wobei das Refresh-Token, der Client-Id, der Client-Secret und die Redirect-URI übermittelt werden.
// Wenn die Antwort erfolgreich ist, wird der neue Access-Token zurückgegeben, andernfalls wird ein Fehler ausgegeben.
func consumeRefreshToken(refreshToken string) (*OAuthToken, error) {
    // Baut die Anfrage
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", ClientId)
	data.Set("client_secret", ClientSecret)
	//data.Set("redirect_uri", RedirectUrl)

	req, err := http.NewRequest("POST", TokenUrl, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    // Sendet die Anfrage mit dem TLS-CLient
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

// ##############################################################################################
// Hier werden Aufräum-Routinen gestartet, die Sessions und Login Versuche Löschen, wenn sie zu alt sind
// ##############################################################################################

// routinesInit startet zwei Hintergrundroutinen (Goroutinen), die periodisch Aufräumarbeiten durchführen.
// Diese Routinen sorgen dafür, dass abgelaufene Logins und SessionTokens regelmäßig entfernt werden.

func routinesInit() {
	go loginStoreCleanupRoutine()
	go sessionStoreCleanupRoutine()
}


// loginStoreCleanupRoutine führt alle 5 Minuten eine Bereinigung des LoginStateStore durch.
// Diese Routine sorgt dafür, dass abgelaufene Logins aus dem Speicher entfernt werden.

func loginStoreCleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute)
		LoginStates.CleanUp()
	}
}

// sessionStoreCleanupRoutine führt alle 5 Minuten eine Bereinigung des SessionTokenStore durch.
// Diese Routine sorgt dafür, dass abgelaufene SessionTokens aus dem Speicher entfernt werden.

func sessionStoreCleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute)
		Sessions.CleanUp()
	}
}