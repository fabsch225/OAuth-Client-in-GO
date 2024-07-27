package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"text/template"
	"time"
	"crypto/tls"
	"log"
	"io/ioutil"
	"crypto/x509"
	"net/http"
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

func InitHTTPClient() {
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
	}

	caCert, err := ioutil.ReadFile(CaCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}

	myCaCert, err := ioutil.ReadFile(CertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	caCertPool.AppendCertsFromPEM(myCaCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		InsecureSkipVerify: true,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	Client = http.Client{Transport: transport} 
}
