package main

import (
	"time"
    "log"
)

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
