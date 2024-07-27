package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"bytes"
	"html/template"
	"time"
	"log"
)

func fetchNotes() ([]Note, error) {
	resp, err := http.Get(ResourceServer)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch notes: %s", resp.Status)
	}

	var notes []Note
	if err := json.NewDecoder(resp.Body).Decode(&notes); err != nil {
		return nil, err
	}
	return notes, nil
}

func createNote(note Note) error {
	jsonData, err := json.Marshal(note)
	if err != nil {
		return err
	}

	resp, err := http.Post(ResourceServer, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create note: %s", resp.Status)
	}

	return nil
}

func deleteNoteByText(text string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/delete?text=%s", ResourceServer, url.QueryEscape(text)), nil)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete note: %s", resp.Status)
	}

	return nil
}

func notesHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("GoNotesSessionToken")
    if err != nil {
        if err == http.ErrNoCookie {
            //redirect to login page
			http.Redirect(w, r, "oa/login", http.StatusTemporaryRedirect)
        }
        // For any other type of error, return a bad request status
        w.WriteHeader(http.StatusBadRequest)
        return
    }
	
	_, isValid := Sessions.GetToken(sessionCookie.Value)
	switch r.Method {
	case http.MethodGet:
		if !isValid {
			//redirect to login page
			http.Redirect(w, r, "oa/login", http.StatusTemporaryRedirect)
		}
		notes, err := fetchNotes()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl, err := template.ParseGlob("../templates/*.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		page := NotesPage{Notes: notes}
		if err := tmpl.Execute(w, page); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	case http.MethodPost:
		if !isValid {
			http.Error(w, "???", http.StatusUnauthorized)
		}

		text := r.FormValue("text")
		date := r.FormValue("date")
		done := r.FormValue("done") == "true"

		note := Note{
			Date: parseDate(date),
			Text: text,
			Done: done,
		}

		if err := createNote(note); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/notes", http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func parseDate(date string) time.Time {
	parsedDate, err := time.Parse("2006-01-02", date)
	if err != nil {
		log.Fatal(err)
	}
	return parsedDate
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" {
		http.Error(w, "Missing 'text' query parameter", http.StatusBadRequest)
		return
	}

	if err := deleteNoteByText(text); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}