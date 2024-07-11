package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"text/template"
	"time"
)

type AuthParams struct {
	AuthUrl             string
	ClientId            string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectUri         string
	ResponseType        string
	Scope               string
	State               string
}

const AuthCodeUrlTemplate = `{{.AuthUrl}}?client_id={{.ClientId}}&code_challenge={{.CodeChallenge}}&code_challenge_method={{.CodeChallengeMethod}}&redirect_uri={{.RedirectUri}}&response_type={{.ResponseType}}&scope={{.Scope}}&state={{.State}}`

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
}

type ExchangeParams struct {
	Code         string
	CodeVerifier string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

const ExchangeBodyTemplate = `grant_type=authorization_code&code={{.Code}}&redirect_uri={{.RedirectURI}}&client_id={{.ClientID}}&client_secret={{.ClientSecret}}&code_verifier={{.CodeVerifier}}`

var (
	oauthStateString string = generateState()
	codeVerifier     string = generateCodeVerifier()
	RedirectUrl      string = "http://37.27.87.77:8089/oa/callback"
	ClientId         string = "Xvu2c0baKdRnNQoJ2YM0uhEXHhRZhf6U5mjucfog"
	ClientSecret     string = "bATdv33lqDRHSsunlWUsaxWOC8Iq5XUMlGINd8Eb8MnBFLQjcS2TEBv9thgdEhspqM7zLiEsxiZm09dA7stdmyaVwaitbzyDMFaS1AgLLYgrdsQN649G9fceDrzZgg9f"
	AuthURL          string = "http://37.27.87.77:9000/application/o/authorize/"
	TokenURL         string = "http://37.27.87.77:9000/application/o/token/"
	UserInfoUrl      string = "http://37.27.87.77:9000/application/o/userinfo/"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir("../static")))
	http.HandleFunc("/oa/login", handleLogin)
	http.HandleFunc("/oa/callback", handleCallback)

	fmt.Println("Started running on http://localhost:8089")
	log.Fatal(http.ListenAndServe(":8089", nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	codeChallenge := generateCodeChallenge(codeVerifier)
	params := AuthParams{
		AuthUrl:             AuthURL,
		ClientId:            ClientId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		RedirectUri:         RedirectUrl,
		ResponseType:        "code",
		Scope:               "notes",
		State:               oauthStateString,
	}
	url2, _ := generateAuthURL(params)
	http.Redirect(w, r, url2, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != oauthStateString {
		log.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, r.FormValue("state"))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")

	params := ExchangeParams{
		ClientSecret: ClientSecret,
		ClientID:     ClientId,
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  RedirectUrl,
	}

	tmpl, err := template.New("ExchangeUrl").Parse(ExchangeBodyTemplate)
	if err != nil {
		log.Printf("Error parsing template: %v\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var ExchangeUrlBody bytes.Buffer
	if err := tmpl.Execute(&ExchangeUrlBody, params); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing template: %v\n", err)
		return
	}
	req, err := http.NewRequest("POST", TokenURL, &ExchangeUrlBody)
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		return
	}

	// Set the appropriate headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Read and process the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error: %s\n", body)
		return
	}

	// Parse the JSON response
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		return
	}

	//test the token
	fmt.Println(tokenResponse)
	req, _ = http.NewRequest("GET", UserInfoUrl, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("failed getting user info: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	newStr := buf.String()

	fmt.Fprintf(w, "{\"Content\": %s\n, \"Token\": %s\n}", newStr, string(body))
}

func generateAuthURL(params AuthParams) (string, error) {
	tmpl, err := template.New("AuthCodeUrl").Parse(AuthCodeUrlTemplate)
	if err != nil {
		return "", err
	}

	var result bytes.Buffer
	err = tmpl.Execute(&result, params)
	if err != nil {
		return "", err
	}

	return result.String(), nil
}

func generateState() string {
	return fmt.Sprintf("st%d", time.Now().UnixNano())
}

func generateCodeVerifier() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	sha := sha256.New()
	sha.Write([]byte(verifier))
	sum := sha.Sum(nil)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum)
}
