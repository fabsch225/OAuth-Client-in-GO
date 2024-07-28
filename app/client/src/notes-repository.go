package main

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