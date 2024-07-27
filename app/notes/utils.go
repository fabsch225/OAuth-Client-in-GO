package main

import (
	"crypto/tls"
	"log"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"net/http"
	"database/sql"
	"fmt"
	"io/ioutil"
	"github.com/golang-jwt/jwt/v4"
)

func validateJwt(source string) (string, bool) {
	token, err := jwt.Parse(source, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return PublicKey, nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return "", false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		note := claims["notes"].(string)
		sub := claims["sub"].(string)
		if note == ResourceId {
			return sub, true
		} else {
			return "", false
		}
	} else {
		return "", false
	}
}

func LoadPublicKey(certFile string) (*rsa.PublicKey, error) {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an RSA public key")
	}

	return publicKey, nil
}

func initDB() {
	var err error
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		DbHost, DbPort, DbUser, DbPassword, DbName)
	Db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	err = Db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to database!")
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
