package main

import (
	"time"
)

func routinesInit() {
	go loginStoreCleanupRoutine()
	go sessionStoreCleanupRoutine()
}

func loginStoreCleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute) // Run cleanup every 5 minutes
		LoginStates.CleanUp()
	}
}

func sessionStoreCleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute) // Run cleanup every 5 minutes
		Sessions.CleanUp()
	}
}