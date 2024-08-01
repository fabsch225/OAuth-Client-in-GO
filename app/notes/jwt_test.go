package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

// ##############################################################################################
// Unit Tests für die validateJwt FUnktion
// ##############################################################################################

func TestValidateJwt(t *testing.T) {
	// Neuer Private Key zum testen
	privateKey, err := createPrivateKey()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	// Public Key aus dem Private Key holen
	publicKey := &privateKey.PublicKey

	// Table Driven Unit Tests
	tests := []struct {
		name        string
		token       string
		expectedSub string
		expectedOk  bool
	}{
		{
			name:        "valid token with correct note",
			token:       createMockToken(ResourceId, "test-sub", privateKey),
			expectedSub: "test-sub",
			expectedOk:  true,
		},
		{
			name:        "valid token with incorrect note",
			token:       createMockToken("wrong-note", "test-sub", privateKey),
			expectedSub: "",
			expectedOk:  false,
		},
		{
			name:        "invalid token signature",
			token:       "invalid.token.signature",
			expectedSub: "",
			expectedOk:  false,
		},
	}

	// Die Tabelle iterieren um die Tests auszuführen
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, ok := validateJwt(tt.token, publicKey)
			if sub != tt.expectedSub || ok != tt.expectedOk {
				t.Errorf("validateJwt() = (%v, %v), want (%v, %v)", sub, ok, tt.expectedSub, tt.expectedOk)
			}
		})
	}
}

// Hilsfunktion um Mock Access Tokens zu erstellen
func createMockToken(note, sub string, key *rsa.PrivateKey) string {
	claims := jwt.MapClaims{
		"notes": note,
		"sub":   sub,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}
	return tokenString
}

func createPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
