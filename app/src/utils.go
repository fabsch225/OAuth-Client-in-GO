package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"text/template"
	"time"
)

func generateAuthURL(params AuthParams) (string, error) {
	tmpl, err := template.New("AuthCodeUrl").Parse(AuthCodeUrlTemplate)
	if err != nil {
		return "", err
	}

	var result bytes.Buffer
	err = tmpl.Execute(&result, params)
	if err != nil {
		return "", err
	}

	return result.String(), nil
}

func generateCSRFTokenSource() string {
	return fmt.Sprintf("csrf-%s", generateCodeVerifier())
}

func generateState() string {
	return fmt.Sprintf("st-%s", generateCodeVerifier())
}

func generateSessionToken() string {
	return generateCodeVerifier()
}

func generateCodeVerifier() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	sha := sha256.New()
	sha.Write([]byte(verifier))
	sum := sha.Sum(nil)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum)
}
