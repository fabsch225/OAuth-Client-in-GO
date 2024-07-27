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

func fetchNotes(token OAuthToken) ([]Note, error) {
	req, err := http.NewRequest("GET", ResourceServer, nil)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token.AccessToken)
	resp, err := Client.Do(req)
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

func createNote(note Note, token OAuthToken) error {
	jsonData, err := json.Marshal(note)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", ResourceServer, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token.AccessToken)
	resp, err := Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create note: %s", resp.Status)
	}
	return nil
}

func deleteNoteByText(text string, token OAuthToken) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/delete?text=%s", ResourceServer, url.QueryEscape(text)), nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token.AccessToken)
	if err != nil {
		return err
	}

	resp, err := Client.Do(req)
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
	
	sessionData, isValid := Sessions.GetData(sessionCookie.Value)
	//error handling depends on the http method. here, just avoid nil pointer dereference
	if (isValid) {
		err = refreshAccessTokenIfPossible(sessionData)
		if (err != nil) {
			log.Printf("cannot refresh Token: %s\n", err.Error)
		}
	}
	token := sessionData.Token
	csrfToken := sessionData.CSRFToken.Source
	csrfTokenClaim := r.FormValue("csrf_token")
	
	switch r.Method {
	case http.MethodGet:
		if !isValid {
			//redirect to login page
			http.Redirect(w, r, "oa/login", http.StatusTemporaryRedirect)
		}
		notes, err := fetchNotes(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl, err := template.ParseGlob("../templates/*.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		page := NotesPage{
			Notes: notes,
			CSRFToken: csrfToken,
		}
		

		if err := tmpl.Execute(w, page); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	case http.MethodPost:
		if !isValid {
			http.Error(w, "???", http.StatusUnauthorized)
		}
		if csrfToken != csrfTokenClaim {
			http.Error(w, "possible CSRF Attack detected", http.StatusInternalServerError)
			return
		}

		text := r.FormValue("text")
		date := r.FormValue("date")
		done := r.FormValue("done") == "true"

		note := Note{
			Date: parseDate(date),
			Text: text,
			Done: done,
		}

		if err := createNote(note, token); err != nil {
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
	
	sessionData, isValid := Sessions.GetData(sessionCookie.Value)
	if !isValid { 
		http.Error(w, "???", http.StatusUnauthorized)
	}
	csrfToken := sessionData.CSRFToken.Source
	csrfTokenClaim := r.FormValue("csrf_token")
	if csrfToken != csrfTokenClaim {
		http.Error(w, "possible CSRF Attack detected", http.StatusInternalServerError)
		return
	}
	err = refreshAccessTokenIfPossible(sessionData)
	if (err != nil) {
		log.Printf("cannot refresh Token: %s\n", err.Error)
	}
	token := sessionData.Token
	text := r.FormValue("text")
	if text == "" {
		http.Error(w, "Missing 'text' query parameter", http.StatusBadRequest)
		return
	}

	if err := deleteNoteByText(text, token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}