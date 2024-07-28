package main

import (
	"time"
)

// routinesInit startet zwei Hintergrundroutinen (Goroutinen), die periodisch Aufräumarbeiten durchführen.
// Diese Routinen sorgen dafür, dass abgelaufene Logins und SessionTokens regelmäßig entfernt werden.

func routinesInit() {
	go loginStoreCleanupRoutine()
	go sessionStoreCleanupRoutine()
}


// loginStoreCleanupRoutine führt alle 5 Minuten eine Bereinigung des LoginStateStore durch.
// Diese Routine sorgt dafür, dass abgelaufene Logins aus dem Speicher entfernt werden.

func loginStoreCleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute)
		LoginStates.CleanUp()
	}
}

// sessionStoreCleanupRoutine führt alle 5 Minuten eine Bereinigung des SessionTokenStore durch.
// Diese Routine sorgt dafür, dass abgelaufene SessionTokens aus dem Speicher entfernt werden.

func sessionStoreCleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute)
		Sessions.CleanUp()
	}
}
