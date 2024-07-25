package main

import (
	"time"
)

// AddToken adds a new access token to the store.
func (store *SessionTokenStore) AddToken(id string, token OAuthToken) {
    store.mu.Lock()
    defer store.mu.Unlock()
	
	entry := SessionTokenData {
		CSRFToken: 		  CSRFToken {
			Source: generateCSRFTokenSource(),
						  },
		Token:            token,
		SessionExpiresAt: time.Now().Add(store.ttl),
	}
    store.tokens[id] = entry
}

// GetToken retrieves an access token from the store by ID.
func (store *SessionTokenStore) GetToken(id string) (*OAuthToken, bool) {
    store.mu.RLock()
    defer store.mu.RUnlock()
    entry, exists := store.tokens[id]
    return &entry.Token, exists
}

// RemoveToken removes an access token from the store by the SessionToken.
func (store *SessionTokenStore) RemoveToken(id string) {
    store.mu.Lock()
    defer store.mu.Unlock()
    delete(store.tokens, id)
}

// IsExpired checks if a specific session token has expired.
func (store *SessionTokenStore) IsExpired(id string) bool {
    store.mu.RLock()
    defer store.mu.RUnlock()
    token, exists := store.tokens[id]
    if !exists {
        return true
    }
    return time.Now().After(token.SessionExpiresAt)
}

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