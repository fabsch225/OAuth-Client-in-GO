package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

var (
	RedirectUrl      string = "https://37.27.87.77:8089/oa/callback"
	ClientId         string = "HQrsYMEXnEksFCMQ1klvt85RIT3Jt8KHSd5uArn0"
	ClientSecret     string = "DGChUUu9f82vhhfaBmEA1KrSPFYwuopTXktkvuOhnuyJt1yyXtjVe8bX9ondAylY0eavD5NxNYQ5z1tPt3pV6k5EAsq3t7x6gYzUT326Ktt8aZfRX92NAOFlGBpGOdOj"
	AuthUrl          string = "https://37.27.87.77:9443/application/o/authorize/"
	TokenUrl         string = "https://37.27.87.77:9443/application/o/token/"
	IntrospectionUrl string = "https://37.27.87.77:9443/application/o/introspect/"
	RevokeUrl        string = "https://37.27.87.77:9443/application/o/revoke/"
	UserInfoUrl      string = "https://37.27.87.77:9443/application/o/userinfo/"
	LogoutUrl        string = "https://37.27.87.77:9443/application/o/notes/end-session/"
	CertFile         string = "../certs/server.crt"
	KeyFile          string = "../certs/server.key"
	CaCertFile       string = "../certs/certificate.crt"
	ResourceServer   string = "https://37.27.87.77:8080/notes"
)

var Sessions      SessionTokenStore   = *NewSessionTokenStore()
var LoginStates   LoginStateStore     = *NewLoginStateStore(1 * time.Minute)
var Client        http.Client

func main() {
	InitHTTPClient()
	http.Handle("/", http.FileServer(http.Dir("../static")))
	http.HandleFunc("/oa/login", handleLogin)
	http.HandleFunc("/oa/callback", handleCallback)
	http.HandleFunc("/notes", notesHandler)
	http.HandleFunc("/notes/delete", deleteHandler)

	server := &http.Server{
        Addr: ":8089",
    }
	fmt.Println("Started running on https://localhost:8089")
	log.Fatal(server.ListenAndServeTLS("../certs/server.crt", "../certs/server.key"))
}