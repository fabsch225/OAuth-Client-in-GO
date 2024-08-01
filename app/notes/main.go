package main

import (
	"database/sql"
	"net/http"
	"fmt"
	"log"
	"time"
	"crypto/rsa"
)

// Note repräsentiert eine Notiz mit Datum, Text, Status (erledigt oder nicht) und Besitzer.
type Note struct {
	Date  time.Time `json:"date"`
	Text  string    `json:"text"`
	Done  bool      `json:"done"`
	Owner string    `json:"owner"`
}

var (
	Db        *sql.DB           // Globale Variable für die Datenbankverbindung
	Client    http.Client       // Globale Variable für den HTTP-Client
	PublicKey *rsa.PublicKey    // Globale Variable für den öffentlichen Schlüssel zur JWT-Validierung

	// Datenbankkonfigurationsvariablen
	DbUser       string = "notes_user"
	DbPassword   string = "123"
	DbName       string = "postgres"
	DbHost       string = "postgres" // Aus dem Docker Compose Netz
	DbPort       string = "5432"

	// OAuth2-Konfigurationsvariablen
	ClientId     string = "HQrsYMEXnEksFCMQ1klvt85RIT3Jt8KHSd5uArn0"
	CertFile     string = "./certs/server.crt"
	KeyFile      string = "./certs/server.key"
	CaCertFile   string = "./certs/certificate.crt"
	ResourceId   string = "ytAwQxEH4lRu48Ae9JjI2epogcJLhSfP" // Wert im JWT bei Anwendung des notes-scopes.
)

func main() {
	// Laden des öffentlichen Schlüssels zur JWT-Validierung
	var err error
	PublicKey, err = LoadPublicKey(CaCertFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Initialisierung der Datenbankverbindung und des HTTP-Clients
	initDB()
	InitHTTPClient()
	defer Db.Close()

	// Festlegen der HTTP-Handler für verschiedene Endpunkte
	http.HandleFunc("/notes", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetNotes(w, r) // Handhabt GET-Anfragen zum Abrufen von Notizen
		case http.MethodPost:
			handleCreateNote(w, r) // Handhabt POST-Anfragen zum Erstellen von Notizen
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/notes/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			handleDeleteNote(w, r) // Handhabt DELETE-Anfragen zum Löschen von Notizen
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Starten des HTTPS-Servers auf Port 8080
	server := &http.Server{
		Addr: ":8080",
	}

	fmt.Println("Api listening on localhost:8080!")
	log.Fatal(server.ListenAndServeTLS("./certs/server.crt", "./certs/server.key"))
}