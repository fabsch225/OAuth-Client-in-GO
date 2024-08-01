package main

import (
	"net/http"
	"strings"
	"encoding/json"
	_ "github.com/lib/pq"
)

// ##############################################################################################
// handleGetNotes verarbeitet GET-Anfragen, um Notizen abzurufen.
// Überprüft das Authorization-Header, validiert das JWT und gibt die Notizen des Benutzers zurück.
// ##############################################################################################

func handleGetNotes(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	owner, valid := validateJwt(accessToken, PublicKey)
	if !valid {
		http.Error(w, "Token invalid", http.StatusUnauthorized)
	}

	// Abfrage der Notizen des Benutzers aus der Datenbank
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


// ##############################################################################################
// handleCreateNote verarbeitet POST-Anfragen, um neue Notizen zu erstellen.
// Überprüft das Authorization-Header, validiert das JWT und fügt eine neue Notiz in die Datenbank ein.
// ##############################################################################################

func handleCreateNote(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	owner, valid := validateJwt(accessToken, PublicKey)
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

	// Einfügen der Notiz in die Datenbank
	_, err := Db.Exec("INSERT INTO notes_user.notes (date, text, done, owner) VALUES ($1, $2, $3, $4)", note.Date, note.Text, doneByte, note.Owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}


// ##############################################################################################
// handleDeleteNote verarbeitet DELETE-Anfragen, um Notizen zu löschen.
// Überprüft das Authorization-Header, validiert das JWT und löscht die Notiz aus der Datenbank.
// ##############################################################################################

func handleDeleteNote(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	owner, valid := validateJwt(accessToken, PublicKey)
	if !valid {
		http.Error(w, "Token invalid", http.StatusUnauthorized)
	}

	text := r.URL.Query().Get("text")
	if text == "" {
		http.Error(w, "Missing 'text' query parameter", http.StatusBadRequest)
		return
	}

	// Löschen der Notiz aus der Datenbank
	_, err := Db.Exec("DELETE FROM notes_user.notes WHERE text = $1 AND owner = $2", text, owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}