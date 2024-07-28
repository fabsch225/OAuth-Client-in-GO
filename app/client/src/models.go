package main

import (
	"time"
	"sync"
)

// zur Darstellung einer Notiz. Enthält das Erstellungsdatum, den Text, einen Boolean, 
// der anzeigt, ob die Notiz erledigt ist, und den Besitzer der Notiz.
type Note struct {
	Date      time.Time `json:"date"`
	Text      string    `json:"text"`
	Done      bool      `json:"done"`
	Owner     string    `json:"owner"`
}

// zur Darstellung einer Seite mit Notizen. Enthält eine Liste von Notizen und einen CSRF-Token zur Vermeidung von CSRF-Angriffen.
type NotesPage struct {
	Notes     []Note
	CSRFToken string
}