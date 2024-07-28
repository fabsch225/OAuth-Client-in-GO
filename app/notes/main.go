package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"strings"
	"crypto/rsa"

	_ "github.com/lib/pq"
)

type Note struct {
	Date  time.Time `json:"date"`
	Text  string    `json:"text"`
	Done  bool      `json:"done"`
	Owner string    `json:"owner"`
}

var Db        *sql.DB
var Client    http.Client
var PublicKey *rsa.PublicKey

var (
	DbUser           string = "notes_user"
	DbPassword       string = "123"
	DbName           string = "postgres"
	DbHost           string = "postgres"
	DbPort           string = "5432"
	ClientId         string = "HQrsYMEXnEksFCMQ1klvt85RIT3Jt8KHSd5uArn0"
	CertFile         string = "./certs/server.crt"
	KeyFile          string = "./certs/server.key"
	CaCertFile       string = "./certs/certificate.crt"
	ResourceId       string = "ytAwQxEH4lRu48Ae9JjI2epogcJLhSfP" //if the notes-scope is applied, this will be the value in the jwt
)

func getNotes(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Authorization header missing", http.StatusUnauthorized)
        return
    }
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	owner, valid := validateJwt(accessToken)
	if !valid {
		http.Error(w, "Token invalid", http.StatusUnauthorized)
	}

	rows, err := Db.Query("SELECT date, text, done, owner FROM notes_user.notes WHERE owner = $1", owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var note Note
		var doneByte byte
		if err := rows.Scan(&note.Date, &note.Text, &doneByte, &note.Owner); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		note.Done = doneByte == 1
		notes = append(notes, note)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(notes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func createNote(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Authorization header missing", http.StatusUnauthorized)
        return
    }
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	owner, valid := validateJwt(accessToken)
	if !valid {
		http.Error(w, "Token invalid", http.StatusUnauthorized)
	}


	var note Note
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	note.Owner = owner
	doneByte := 0
	if note.Done {
		doneByte = 1
	}

	_, err := Db.Exec("INSERT INTO notes_user.notes (date, text, done, owner) VALUES ($1, $2, $3, $4)", note.Date, note.Text, doneByte, note.Owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func deleteNote(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Authorization header missing", http.StatusUnauthorized)
        return
    }
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	owner, valid := validateJwt(accessToken)
	if !valid {
		http.Error(w, "Token invalid", http.StatusUnauthorized)
	}

	text := r.URL.Query().Get("text")
	if text == "" {
		http.Error(w, "Missing 'text' query parameter", http.StatusBadRequest)
		return
	}

	_, err := Db.Exec("DELETE FROM notes_user.notes WHERE text = $1 AND owner = $2", text, owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	var err error
	PublicKey, err = LoadPublicKey(CaCertFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	initDB()
	InitHTTPClient()
	defer Db.Close()

	http.HandleFunc("/notes", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getNotes(w, r)
		case http.MethodPost:
			createNote(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/notes/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteNote(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := &http.Server{
        Addr: ":8080",
    }

	fmt.Println("Api listening on localhost:8080")
	log.Fatal(server.ListenAndServeTLS("./certs/server.crt", "./certs/server.key"))
}
