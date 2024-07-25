package main

import (
	"time"
)
//TODO add routine for Sessions
func routinesInit() {
	go loginStoreCleanupRoutine()
}

func loginStoreCleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute) // Run cleanup every 5 minutes
		LoginStates.CleanUp()
	}
}