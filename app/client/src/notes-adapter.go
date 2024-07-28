// ##############################################################################################
// Hier wird der Resource Server abgerufen
// Zur Authtorizierung wird ein Access-Token (JWT) verwendet, der von Authentik signiert ist
// Der Scope "notes" ist hier relevant. Idealerweise ist der in den JWT eingebettet
// ##############################################################################################

package main

import (
	"net/http"
	"net/url"
	"fmt"
	"encoding/json"
	"bytes"
)

// ##############################################################################################
// fetchNotes ruft die Notizen des Benutzers vom Ressourcenspeicher ab.
// Es sendet eine GET-Anfrage an den ResourceServer mit dem Access-Token (JWT) im Header.
// ##############################################################################################

func fetchNotes(token OAuthToken) ([]Note, error) {
	// Baut die Anfrage
	req, err := http.NewRequest("GET", ResourceServer, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token.AccessToken)

	// Sendet die Anfrage mit dem TLS-CLient
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

// ##############################################################################################
// createNote erstellt eine neue Notiz auf dem Ressource Server.
// Es sendet eine POST-Anfrage mit den Notizdaten als JSON und dem Access-Token (JWT) im Header.
// ##############################################################################################

func createNote(note Note, token OAuthToken) error {
	// Kodiert die neue Notiz in JSON
	jsonData, err := json.Marshal(note)
	if err != nil {
		return err
	}
	// Baut die Anfrage
	req, err := http.NewRequest("POST", ResourceServer, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token.AccessToken)

	// Sendet die Anfrage mit dem TLS-CLient
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

// ##############################################################################################
// deleteNoteByText löscht eine Notiz anhand ihres Textinhalts vom Ressource Server.
// Es sendet eine DELETE-Anfrage mit dem Text als Query-Parameter und dem Access-Token (JWT) im Header.
// ##############################################################################################

func deleteNoteByText(text string, token OAuthToken) error {
	// Baut die Angrage
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/delete?text=%s", ResourceServer, url.QueryEscape(text)), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token.AccessToken)

	// Sendet die Anfrage mit dem TLS-CLient
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