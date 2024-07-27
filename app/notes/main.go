package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
)

var (
	DbUser     string = "notes_user"
	DbPassword string = "123"
	DbName     string = "postgres"
	DbHost     string = "localhost"
	DbPort     string = "5432"
)

type Note struct {
	Date  time.Time `json:"date"`
	Text  string    `json:"text"`
	Done  bool      `json:"done"`
	Owner string    `json:"owner"`
}

var Db *sql.DB

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

func getNotes(w http.ResponseWriter, r *http.Request) {
	rows, err := Db.Query("SELECT date, text, done, owner FROM notes_user.notes")
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
	var note Note
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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
	text := r.URL.Query().Get("text")
	if text == "" {
		http.Error(w, "Missing 'text' query parameter", http.StatusBadRequest)
		return
	}

	_, err := Db.Exec("DELETE FROM notes_user.notes WHERE text = $1", text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	initDB()
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
	fmt.Println("Api listening on localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
