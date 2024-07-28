package main

import (
	"net/url"
	"net/http"
	"strings"
	"log"
)

// handleLogout behandelt die Abmeldung des Benutzers.
// Es prüft die Gültigkeit des Sitzungstokens, widerruft das Token und leitet den Benutzer zur Abmeldeseite weiter.

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Liest das Sitzungscookie
	sessionCookie, err := r.Cookie("GoNotesSessionToken")
    if err != nil {
        if err == http.ErrNoCookie {
            // Wenn kein Sitzungscookie vorhanden ist, wird zur Login-Seite umgeleitet
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

	// Überprüft das CSRF-Token, um CSRF-Angriffe zu verhindern
	if csrfToken != csrfTokenClaim {
		http.Error(w, "possible CSRF Attack detected", http.StatusUnauthorized)
		return
	}

	// Widerruft das Token
	err = revokeToken(token.RefreshToken)
	if err != nil {
		http.Error(w, "Token Revokation failed", http.StatusInternalServerError)
		return
	}

	// Entfernt das Sitzungstoken und leitet zur Abmeldeseite weiter
	Sessions.RemoveToken(sessionCookie.Value)
	http.Redirect(w, r, LogoutUrl, http.StatusSeeOther)
}


// revokeToken widerruft das gegebene Token, indem eine HTTP-POST-Anfrage an den Token-Widerrufs-Endpunkt gesendet wird.

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

	// Sendet die Anfrage
	_, err = Client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v\n", err)
		return err
	}
	return nil
}
