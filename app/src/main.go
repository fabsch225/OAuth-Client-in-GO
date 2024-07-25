package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

var (
	RedirectUrl      string = "http://37.27.87.77:8089/oa/callback"
	ClientId         string = "HQrsYMEXnEksFCMQ1klvt85RIT3Jt8KHSd5uArn0"
	ClientSecret     string = "DGChUUu9f82vhhfaBmEA1KrSPFYwuopTXktkvuOhnuyJt1yyXtjVe8bX9ondAylY0eavD5NxNYQ5z1tPt3pV6k5EAsq3t7x6gYzUT326Ktt8aZfRX92NAOFlGBpGOdOj"
	AuthURL          string = "http://37.27.87.77:9000/application/o/authorize/"
	TokenURL         string = "http://37.27.87.77:9000/application/o/token/"
	UserInfoUrl      string = "http://37.27.87.77:9000/application/o/userinfo/"
)

var Sessions      SessionTokenStore   = *NewSessionTokenStore()
var LoginStates   LoginStateStore     = *NewLoginStateStore(1 * time.Minute)

func main() {
	http.Handle("/", http.FileServer(http.Dir("../static")))
	http.HandleFunc("/oa/login", handleLogin)
	http.HandleFunc("/oa/callback", handleCallback)

	fmt.Println("Started running on http://localhost:8089")
	log.Fatal(http.ListenAndServe(":8089", nil))
}