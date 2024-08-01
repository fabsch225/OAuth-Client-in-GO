package main

import (
	"testing"
	"time"
)

// Eine Mock Version vom SessionTokenStore, bei dem die Sessions schnell ablaufen
func mockNewSessionTokenStore() *SessionTokenStore {
    return &SessionTokenStore{
        tokens: make(map[string]SessionTokenData),
		ttl: time.Second * 10,
    }
}

// Simuliere Refresh Token Flow
func mockConsumeRefreshToken(refreshToken string) (*OAuthToken, error) {
	return &OAuthToken{
		AccessToken:  generateSessionToken(), //es ist nicht wichtig, ob das ein "guter" Mock Token ist
		RefreshToken: generateSessionToken(),
	}, nil
}


// ##############################################################################################
// Tests für SessionTokenStore
// ##############################################################################################

func TestAddToken(t *testing.T) {
	store := mockNewSessionTokenStore()
	token := OAuthToken{AccessToken: "access", RefreshToken: "refresh"}
	sessionToken, csrfToken := store.AddToken(token)

	if sessionToken == "" || csrfToken == "" {
		t.Errorf("Expected non-empty sessionToken and csrfToken")
	}

	storedToken, exists := store.GetToken(sessionToken)
	if !exists {
		t.Errorf("Expected token to exist in the store")
	}
	if storedToken.AccessToken != token.AccessToken {
		t.Errorf("Expected AccessToken %v, got %v", token.AccessToken, storedToken.AccessToken)
	}
}

func TestGetToken(t *testing.T) {
	store := mockNewSessionTokenStore()
	token := OAuthToken{AccessToken: "access", RefreshToken: "refresh"}
	sessionToken, _ := store.AddToken(token)

	storedToken, exists := store.GetToken(sessionToken)
	if !exists {
		t.Errorf("Expected token to exist in the store")
	}
	if storedToken.AccessToken != token.AccessToken {
		t.Errorf("Expected AccessToken %v, got %v", token.AccessToken, storedToken.AccessToken)
	}
}

func TestRemoveToken(t *testing.T) {
	store := mockNewSessionTokenStore()
	token := OAuthToken{AccessToken: "access", RefreshToken: "refresh"}
	sessionToken, _ := store.AddToken(token)

	store.RemoveToken(sessionToken)

	_, exists := store.GetToken(sessionToken)
	if exists {
		t.Errorf("Expected token to be removed from the store")
	}
}

func TestIsExpired(t *testing.T) {
	store := mockNewSessionTokenStore()
	token := OAuthToken{AccessToken: "access", RefreshToken: "refresh"}
	sessionToken, _ := store.AddToken(token)

	// Jetzt sollte der Session Token abgelaufen sein
	time.Sleep(11 * time.Second)

	if !store.IsExpired(sessionToken) {
		t.Errorf("Expected token to be expired")
	}
}

func TestCleanUp(t *testing.T) {
	store := mockNewSessionTokenStore()
	token := OAuthToken{AccessToken: "access", RefreshToken: "refresh"}
	sessionToken, _ := store.AddToken(token)

	// Jetzt sollte der Session Token abgelaufen sein
	time.Sleep(11 * time.Second)

	store.CleanUp()

	_, exists := store.GetToken(sessionToken)
	if exists {
		t.Errorf("Expected expired token to be cleaned up")
	}
}


// ##############################################################################################
// Tests für LoginStateStore
// ##############################################################################################

func TestAddState(t *testing.T) {
	store := NewLoginStateStore(time.Second * 10)
	state := "login-state"
	codeVerifier := "code-verifier"
	store.AddState(state, codeVerifier)

	retrievedCodeVerifier := store.Retrieve(state)
	if retrievedCodeVerifier != codeVerifier {
		t.Errorf("Expected codeVerifier %v, got %v", codeVerifier, retrievedCodeVerifier)
	}
}

func TestRetrieve(t *testing.T) {
	store := NewLoginStateStore(time.Second * 10)
	state := "login-state"
	codeVerifier := "code-verifier"
	store.AddState(state, codeVerifier)

	retrievedCodeVerifier := store.Retrieve(state)
	if retrievedCodeVerifier != codeVerifier {
		t.Errorf("Expected codeVerifier %v, got %v", codeVerifier, retrievedCodeVerifier)
	}

	// Der state darf nicht mehr da sein
	retrievedCodeVerifier = store.Retrieve(state)
	if retrievedCodeVerifier != "" {
		t.Errorf("Expected empty codeVerifier after state retrieval, got %v", retrievedCodeVerifier)
	}
}

func TestContains(t *testing.T) {
	store := NewLoginStateStore(time.Second * 10)
	state := "login-state"
	codeVerifier := "code-verifier"
	store.AddState(state, codeVerifier)

	if !store.Contains(state) {
		t.Errorf("Expected state to be present in the store")
	}

	// Jetzt sollte der State Token abgelaufen sein (jedenfalls sagt der store das)
	time.Sleep(11 * time.Second)

	if store.Contains(state) {
		t.Errorf("Expected state to be expired and removed from the store")
	}
}

func TestLoginStateStoreCleanUp(t *testing.T) {
	store := NewLoginStateStore(time.Second * 10)
	state := "login-state"
	codeVerifier := "code-verifier"
	store.AddState(state, codeVerifier)

	// Jetzt sollte der State Token abgelaufen sein (jedenfalls sagt der store das)
	time.Sleep(11 * time.Second)

	store.CleanUp()

	if store.Contains(state) {
		t.Errorf("Expected expired state to be cleaned up")
	}
}