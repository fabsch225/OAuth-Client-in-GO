package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"net/url"
	"strings"
	"html/template"
)

// ##############################################################################################
// handleLogin behandelt den OAuth2-Login-Prozess.
// Es generiert einen Code-Verifier und einen State, speichert diesen im LoginStateStore, 
// und leitet den Benutzer zur OAuth2-Authorisierungs-URL weiter.

// Konkret wird "Proof Key for Code Exchange" (PKCE) nach https://datatracker.ietf.org/doc/html/rfc7636#section-4
// imlpementiert. Da es sich nicht um einen Öffentlichen Client handelt ist das nach OAuth nicht notwendig,
// wird aber von Authentik verlangt.

// Um CSRF Angriffe zu verhindern, wird nach https://datatracker.ietf.org/doc/html/rfc6749#section-10.12 ein state Parameter
// mitgeliefert. Später Authentifiziert sich der Browser ebenfalls einem Session-Cookie und CSRF-Token der in das
// Formular eingebettet ist. Das hat aber nichts mit dem hier zu tun.
// ##############################################################################################

func handleLogin(w http.ResponseWriter, r *http.Request) {
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)
	state := generateState()
	LoginStates.AddState(state, codeVerifier)
	params := url.Values{}
	params.Add("client_id", ClientId)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")
	params.Add("redirect_uri", RedirectUrl)
	params.Add("response_type", "code")

	// Der notes Scope wird in den Access Token eingebettet: In Authentik ist eine "Resource-Id" 
	// festgelegt: Im JWT sieht das so aus: "notes": "<Id>". Der Resource Server verifiziert das dann
	// "offline_access" bedeutet, das Authentik einen refresh Token mitsendet

	params.Add("scope", "notes offline_access")
	params.Add("state", state)

	authUrlWithParams := AuthUrl + "?" + params.Encode()
	http.Redirect(w, r, authUrlWithParams, http.StatusTemporaryRedirect)
}

// ##############################################################################################
// handleCallback behandelt den Rückruf von der OAuth2-Authentifizierungs-URL.
// Es überprüft den Zustand, fordert ein Token vom Token-Endpunkt an, und speichert das Token in einer Sitzung.
// ##############################################################################################

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if !LoginStates.Contains(state) {
		log.Printf("invalid oauth state: '%s'", state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	codeVerifier := LoginStates.Retrieve(state)

	code := r.FormValue("code")

	// Nutzt den Authorization Code um einen Access Token abzufragen
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("redirect_uri", RedirectUrl)
	params.Add("client_id", ClientId)
	params.Add("client_secret", ClientSecret)
	params.Add("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", TokenUrl, strings.NewReader(params.Encode()))
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Sendet die Anfrage mit dem TLS-CLient
	resp, err := Client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	// Liest und verarbeitet die Antwort
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error: %s\n", body)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	// Parse die JSON-Antwort
	var tokenResponse OAuthToken
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		log.Printf("Error parsing response: %v\n", err)
		return
	}

	//Eine neue Session wird registriert
	sessionToken, _ := Sessions.AddToken(tokenResponse)
	
	//den Sessiontoken als Cookie setzen
	http.SetCookie(w, &http.Cookie{
        Name:     "GoNotesSessionToken",
        Value:    sessionToken,
        Path:     "/",
        Domain:   "37.27.87.77",
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
        Secure:   true,
    })

	//zurück zur Anwendung, nun mit der angemeldeten Session
	http.Redirect(w, r, ApplicationUrl, http.StatusFound)
}

// ##############################################################################################
// handleLogout behandelt die Abmeldung des Benutzers.
// Es prüft die Gültigkeit des Sessiontoken, widerruft das Token und leitet den Benutzer zur Abmeldeseite weiter.
// ##############################################################################################

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Liest das Sitzungscookie
	sessionCookie, err := r.Cookie("GoNotesSessionToken")
    if err != nil {
        if err == http.ErrNoCookie {
            // Wenn kein Sessiontoken vorhanden ist, wird zur Login-Seite umgeleitet
			http.Redirect(w, r, "oa/login", http.StatusTemporaryRedirect)
        }
        // Bei anderen Fehlern wird ein Bad Request Status zurückgegeben
        w.WriteHeader(http.StatusBadRequest)
        return
    }
	
	// Überprüft die Gültigkeit des Sitzungstokens
	sessionData, isValid := Sessions.GetData(sessionCookie.Value)
	// Fehlerbehandlung basierend auf der HTTP-Methode, hier wird nur eine Nullzeiger-Dereferenzierung vermieden
	if isValid {
		Sessions.RefreshAccess(sessionCookie.Value)
	}
	token := sessionData.Token
	csrfToken := sessionData.CSRFToken.Source
	csrfTokenClaim := r.FormValue("csrf_token")

	// Überprüft das CSRF-Token
	if csrfToken != csrfTokenClaim {
		http.Error(w, "possible CSRF Attack detected", http.StatusUnauthorized)
		return
	}

	// Widerruft das Refresh-Token
	err = revokeToken(token.RefreshToken)
	if err != nil {
		http.Error(w, "Token Revokation failed", http.StatusInternalServerError)
		return
	}

	// Entfernt das Sitzungstoken und leitet zur Abmeldeseite von Authentik weiter
	Sessions.RemoveToken(sessionCookie.Value)
	http.Redirect(w, r, LogoutUrl, http.StatusSeeOther)
}

// ##############################################################################################
// revokeToken widerruft das gegebene Token, 
// indem eine HTTP-POST-Anfrage an den Token-Widerrufs-Endpunkt gesendet wird.
// ##############################################################################################

func revokeToken(token string) error {
	params := url.Values{}
	params.Add("client_id", ClientId)
	params.Add("client_secret", ClientSecret)
	params.Add("token", token)

	// Erstellt eine neue HTTP-POST-Anfrage zum Widerruf des Tokens
	req, err := http.NewRequest("POST", RevokeUrl, strings.NewReader(params.Encode()))
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		return err
	}

	// Setzt den entsprechenden Header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Sendet die Anfrage mit dem TLS-CLient
	_, err = Client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v\n", err)
		return err
	}
	return nil
}


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

// ##############################################################################################
// notesHandler verarbeitet Anfragen an den /notes-Endpunkt.
// Es unterstützt sowohl GET- als auch POST-Methoden und implementiert die entsprechende Logik 
// für das Abrufen und Erstellen von Notizen.
// ##############################################################################################

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

// ##############################################################################################
// deleteHandler verarbeitet Anfragen an den /notes/delete-Endpunkt.
// Es unterstützt die DELETE-Methode und implementiert die Logik zum Löschen einer Notiz anhand ihres Textinhalts.
// ##############################################################################################

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