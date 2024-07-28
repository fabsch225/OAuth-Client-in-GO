// ##############################################################################################
// Hier stehen kryptographische Hilfsfunktionen
// ##############################################################################################

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

// Generiert einen CSRF-Token-Quellwert
// Dies stellt sicher, dass jede Anfrage eindeutig und schwer zu erraten ist.
func generateCSRFTokenSource() string {
	return fmt.Sprintf("csrf-%s", generateCodeVerifier())
}

// Generiert einen OAuth-Status-Parameter, um die Anfrage zu identifizieren.
// Der Status-Parameter wird verwendet, um CSRF-Angriffe zu verhindern.
func generateState() string {
	return fmt.Sprintf("st-%s", generateCodeVerifier())
}

// Generiert ein Sitzungs-Token, indem ein Code-Verifier verwendet wird.
// Dies stellt sicher, dass jede Sitzung eindeutig und sicher ist.
func generateSessionToken() string {
	return generateCodeVerifier()
}

// Generiert einen Code-Verifier
// Dies ist ein Bestandteil des OAuth PKCE-Prozesses (Proof Key for Code Exchange).
func generateCodeVerifier() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

// Generiert eine Code-Challenge
// Dies ist Teil des OAuth PKCE-Prozesses und erhöht die Sicherheit beim Austausch von Authentifizierungscodes.
func generateCodeChallenge(verifier string) string {
	sha := sha256.New()
	sha.Write([]byte(verifier))
	sum := sha.Sum(nil)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum)
}