// ##############################################################################################
// Autor: Fabian Schuler
// Datum: 28.07.2024
// ##############################################################################################

package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

// zur Darstellung eines OAuth2-Tokens, das verschiedene Informationen wie Access-Token, Token-Typ, 
// Gültigkeitsdauer und optionale Refresh- und ID-Tokens enthält.
type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
}

var (
	ClientId         string = "HQrsYMEXnEksFCMQ1klvt85RIT3Jt8KHSd5uArn0"
	ClientSecret     string = "DGChUUu9f82vhhfaBmEA1KrSPFYwuopTXktkvuOhnuyJt1yyXtjVe8bX9ondAylY0eavD5NxNYQ5z1tPt3pV6k5EAsq3t7x6gYzUT326Ktt8aZfRX92NAOFlGBpGOdOj"

	//Endpoints von Authentik
	AuthUrl          string = "https://37.27.87.77:9443/application/o/authorize/"
	TokenUrl         string = "https://37.27.87.77:9443/application/o/token/"
	RevokeUrl        string = "https://37.27.87.77:9443/application/o/revoke/"
	LogoutUrl        string = "https://37.27.87.77:9443/application/o/notes/end-session/"

	// Die URLs des Clients und des Resource Servers
	ResourceServer   string = "https://37.27.87.77:8080/notes"
	ApplicationUrl   string = "https://37.27.87.77:8089/notes"
	RedirectUrl      string = "https://37.27.87.77:8089/oa/callback"

	// Zertifikate: Der Resource-Server und der Client Benutzen jeweils CertFile und KeyFile
	// CaCertFile ist der public key von Authentik
	CertFile         string = "../certs/server.crt"
	KeyFile          string = "../certs/server.key"
	CaCertFile       string = "../certs/certificate.crt"
	AuthentikCA      string = "../certs/authentik_default_certificate.crt"

	// Instanz eines SessionTokenStore zum Speichern von Session-Tokens.
	Sessions SessionTokenStore = *NewSessionTokenStore()

	// Instanz eines LoginStateStore zum Verwalten von laufenden Authorization Flows
	// In der Menge werden die state-Parameter des authorization-Flows gespeichert
	LoginStates LoginStateStore = *NewLoginStateStore(1 * time.Minute)

	// HTTP-Client für Anfragen an den Resource Server und Authentik.
	Client http.Client
)

func main() {
	InitHTTPClient()

	// Richtet den HTTPS-Server ein, um statische Dateien aus dem Verzeichnis "../static" zu bedienen.
	// Für die login Seite und die CSS Dateien 
	http.Handle("/", http.FileServer(http.Dir("../static")))

	// Richtet die Routen für OAuth und Notizen ein
	http.HandleFunc("/oa/login", handleLogin)
	http.HandleFunc("/oa/callback", handleCallback)
	http.HandleFunc("/oa/logout", handleLogout)
	http.HandleFunc("/notes", notesHandler)
	http.HandleFunc("/notes/delete", deleteHandler)
	
	
	server := &http.Server{
		Addr: ":8089",
	}

	fmt.Println("Started running on https://localhost:8089")

	// Startet den HTTPS-Server und verwendet die angegebenen Zertifikats- und Schlüsseldateien.
	// Falls ein Fehler auftritt, wird dieser protokolliert und die Anwendung beendet.
	log.Fatal(server.ListenAndServeTLS(CertFile, KeyFile))
}


// Initialisiert den HTTP-Client mit TLS-Konfiguration.
// Damit werden später (Rück)Anfragen and den Resource Server und an Authentik gesendet
func InitHTTPClient() {
	// Lädt die Zertifikate und erstellt einen TLS-konfigurierten Transport für den Client.
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

	//Das Zertifikat von Authentik und das des Resource Servers werden geladen
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	caCertPool.AppendCertsFromPEM(myCaCert)

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,

		// Authentik benutzt manchmal trotzdem ein anderes Zertifikat, was zu einem Fehler führt:
		// ...doesn't contain any IP SANs. Deswegen hier eine potentielle Sicherheitslücke
		InsecureSkipVerify: true,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	Client = http.Client{Transport: transport} 
}
