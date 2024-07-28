package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"bytes"
	"html/template"
	"time"
)

// CSRF-Schutz (Cross-Site Request Forgery):
// Bei CSRF-Angriffen wird ein bösartiges Website-Skript verwendet, um unbefugt Aktionen im Namen eines authentifizierten Benutzers durchzuführen.
// Um dies zu verhindern, wird ein CSRF-Token verwendet. Ein CSRF-Token ist ein eindeutiger, zufällig generierter Wert, der bei jeder HTTP-Anfrage eines Benutzers gesendet wird.
// Der Server überprüft, ob der empfangene CSRF-Token mit dem auf der Serverseite gespeicherten Token übereinstimmt.
// Wenn die Tokens nicht übereinstimmen, wird die Anfrage als potenziell bösartig erkannt und abgelehnt.
// Dieser Mechanismus stellt sicher, dass nur legitime Anfragen von der echten Benutzer-Sitzung akzeptiert werden.
// 
//
// Da die Anwendig vollständig auf Javascript verzichtet (auch kein HTMX) fallen viele Angriffsvektoren weg.
// 
// Konkret werden CSRF Tokens in das Formular eingebettet, damit man keine Operationen ausführen kann,
// indem das Opfer einen malicious link klickt, während die Seite in einem anderen Tab offen ist (und die Session aktiv).


// fetchNotes ruft die Notizen des Benutzers vom Ressourcenspeicher ab.
// Es sendet eine GET-Anfrage an den ResourceServer mit dem Access-Token (JWT) im Header.

func fetchNotes(token OAuthToken) ([]Note, error) {
	req, err := http.NewRequest("GET", ResourceServer, nil)
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

	// Die erhaltenen Notizen zurückgeben 
	var notes []Note
	if err := json.NewDecoder(resp.Body).Decode(&notes); err != nil {
		return nil, err
	}
	return notes, nil
}


// createNote erstellt eine neue Notiz auf dem Ressource Server.
// Es sendet eine POST-Anfrage mit den Notizdaten als JSON und dem Access-Token (JWT) im Header.

func createNote(note Note, token OAuthToken) error {
	jsonData, err := json.Marshal(note)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", ResourceServer, bytes.NewBuffer(jsonData))
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


// deleteNoteByText löscht eine Notiz anhand ihres Textinhalts vom Ressource Server.
// Es sendet eine DELETE-Anfrage mit dem Text als Query-Parameter und dem Access-Token (JWT) im Header.

func deleteNoteByText(text string, token OAuthToken) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/delete?text=%s", ResourceServer, url.QueryEscape(text)), nil)
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

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete note: %s", resp.Status)
	}

	return nil
}


// notesHandler verarbeitet Anfragen an den /notes-Endpunkt.
// Es unterstützt sowohl GET- als auch POST-Methoden und implementiert die entsprechende Logik 
// für das Abrufen und Erstellen von Notizen.

func notesHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("GoNotesSessionToken")
    if err != nil {
        if err == http.ErrNoCookie {
            http.Redirect(w, r, "oa/login", http.StatusTemporaryRedirect)
            return
        }
        w.WriteHeader(http.StatusBadRequest)
        return
    }

	sessionData, isValid := Sessions.GetData(sessionCookie.Value)
	if isValid {
		// Wenn nötig einen Neuen Access Token anfragen (mit dem Refresh Token)
		Sessions.RefreshAccess(sessionCookie.Value)
	}
	token := sessionData.Token
	csrfToken := sessionData.CSRFToken.Source
	csrfTokenClaim := r.FormValue("csrf_token")

	switch r.Method {
	case http.MethodGet:
		// kontextspezifisches Exception handling:
		// GET wird nur dann angefragt, wenn man die Haupt-Seite /notes aufruft:
		// Falls die Session abgelaufen ist, einfach zur Anmeldung Umleiten
		// CSRF-Abwehr ist hier nicht nötig (nur GET)
		if !isValid {
			http.Redirect(w, r, "oa/login", http.StatusTemporaryRedirect)
			return
		}
		notes, err := fetchNotes(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Lade mehrere Dateien auf einmal. Die Dateien bilden Komponenten (blocks) die untereinander 
		// verknüpft sind
		tmpl, err := template.ParseGlob("../templates/*.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Die Notizen und der CSRF-Token werden in das Template eingebettet
		// Der Token wird in jedes Formular so eingebettet: <input type="hidden" name="csrf_token"...>
		// sodass beim aufrufen der Token mitgeliefert wird. So kommen die Anfragen garantiert vom
		// Browser-Tab des Benutzers
		page := NotesPage{
			Notes:     notes,
			CSRFToken: csrfToken,
		}
		if err := tmpl.Execute(w, page); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	case http.MethodPost:
		// kontextspezifisches Exception handling:
		if !isValid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if csrfToken != csrfTokenClaim {
			http.Error(w, "Possible CSRF attack detected", http.StatusUnauthorized)
			return
		}

		// Aus dem Form-Post ein Note-Struct erstellen
		text := r.FormValue("text")
		date := r.FormValue("date")
		done := r.FormValue("done") == "true"
		parsedDate, err := parseDate(date)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		note := Note{
			Date: parsedDate,
			Text: text,
			Done: done,
		}

		if err := createNote(note, token); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Wieder auf die Seite der Anwendung Umleiten
		http.Redirect(w, r, "/notes", http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}


// parseDate konvertiert ein Datum im Format "YYYY-MM-DD" in einen time.Time-Wert.

func parseDate(date string) (time.Time, error) {
	return time.Parse("2006-01-02", date)
}


// deleteHandler verarbeitet Anfragen an den /notes/delete-Endpunkt.
// Es unterstützt die DELETE-Methode und implementiert die Logik zum Löschen einer Notiz anhand ihres Textinhalts.

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("GoNotesSessionToken")
    if err != nil {
        if err == http.ErrNoCookie {
            http.Redirect(w, r, "oa/login", http.StatusTemporaryRedirect)
            return
        }
        w.WriteHeader(http.StatusBadRequest)
        return
    }

	sessionData, isValid := Sessions.GetData(sessionCookie.Value)
	if !isValid { 
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	csrfToken := sessionData.CSRFToken.Source
	csrfTokenClaim := r.FormValue("csrf_token")
	if csrfToken != csrfTokenClaim {
		http.Error(w, "Possible CSRF attack detected", http.StatusInternalServerError)
		return
	}
	// Wenn nötig einen Neuen Access Token anfragen (mit dem Refresh Token)
	Sessions.RefreshAccess(sessionCookie.Value)
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
