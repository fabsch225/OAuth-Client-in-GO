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

// ##############################################################################################
// validateJwt überprüft das JWT-Token und validiert es gegen den gegebenen RSA-öffentlichen Schlüssel.
// Gibt den Benutzer (sub) zurück, wenn das Token gültig ist und die "notes"-Anspruch den erwarteten Wert hat.
// ##############################################################################################

func validateJwt(source string, key *rsa.PublicKey) (string, bool) {
	token, err := jwt.Parse(source, func(token *jwt.Token) (interface{}, error) {
		// Nur RSA ist unterstützt
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return "", false
	}

	// Überprüfen der Ansprüche des Tokens
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

// ##############################################################################################
// LoadPublicKey lädt den öffentlichen Schlüssel aus einer Zertifikatsdatei.
// ##############################################################################################

func LoadPublicKey(certFile string) (*rsa.PublicKey, error) {
	// Zertifikatsdatei lesen
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	// PEM-Daten dekodieren
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Zertifikat parsen
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Extrahieren des öffentlichen Schlüssels
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an RSA public key")
	}

	return publicKey, nil
}

// ##############################################################################################
// initDB initialisiert die Verbindung zur Datenbank und prüft die Verbindung.
// ##############################################################################################

func initDB() {
	var err error
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		DbHost, DbPort, DbUser, DbPassword, DbName)
	Db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Prüfen der Datenbankverbindung
	err = Db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to database!")
}

// ##############################################################################################
// InitHTTPClient initialisiert den HTTP-Client mit TLS-Konfiguration.
// Lädt die Schlüssel und Zertifikate und konfiguriert die Transportebene des Clients.
// ##############################################################################################

func InitHTTPClient() {
	// Laden des Schlüsselpaars
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
	}

	// Lesen des CA-Zertifikats
	caCert, err := ioutil.ReadFile(CaCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}

	myCaCert, err := ioutil.ReadFile(CertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}

	// Erstellen des CA-Zertifikatspools
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	caCertPool.AppendCertsFromPEM(myCaCert)

	// TLS-Konfiguration
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
	}

	// Konfigurieren des HTTP-Transports
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	Client = http.Client{Transport: transport} 
}
