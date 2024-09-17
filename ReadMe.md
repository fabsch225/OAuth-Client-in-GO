# Microservices mit GO Projekt Fabian Schuller
## Motivation

Dieses Projekt ist eine Beispielhafte implementierung des OAuth Protokolls. Um die Abläufe zu demonstrieren, ist der Client eigens implementiert.

## Übersicht

Das Projekt besteht aus einem OAuth Client (ein Webserver) und einem Resource Server mit Datenbankandbindung
Das Projekt benutzt eine Authentik Instanz (per Docker Compose) als OAuth Provider. 
Man muss einige Konfigurationen in der Benutzer-Oberfläche von Authentik vornehmen, deswegen wäre es praktisch direkt
auf dem Knoten zu testen. (sonst müsste man die Anwendung einrichten und Client Secret / Client Id im Quellcode anpassen)
Um das Projekt zu starten, muss man die beiden Docker Compose dateien ausführen. (falls noch nicht geschehen)

### Bibliotheken und andere fremde Inhalte
Abgesehen von einer JWT Bibliothek (github.com/golang-jwt/jwt/v4) wird nur die Standardbibliothek benutzt. 
Das Docker-Compose Setup ist im wesentlichen von der Authentik Website übernommen.
Der Client und der Resource Server sind vollständig selbst implenentiert.

## OAuth Architektur

- Der Client führt den Authorization Code Flow aus, und speichert Access und Refresh Token unter einem SessionToken ab
- Im Browser wird dann ein Session Cookie gespeichert (und in die Website ein CSRF-Token eingebettet)
- Der "notes"-Scope wird in den Access Token (JWT) kodiert
- Der Client kann damit dann Anfragen an den Resource Server senden
- In der Datenbank sind die Notizen schlicht unter dem Subject des Tokens gespeichert
- Postgres ist von aussen nicht erreichbar, überall ist TLS benutzt 

## Projekt Struktur

```plaintext
projekt
├── app
│   ├── client
│   │   ├── certs                 # Zertifikate für Client
│   │   ├── src                   # Quellcode für Client
│   │   │   ├── crypto-utils.go
│   │   │   ├── go.mod
│   │   │   ├── go.sum
│   │   │   ├── handlers.go       # Oauth Logik und Api zum Resource Server
│   │   │   ├── main.go
│   │   │   ├── models.go         # Structs um in die Templates zu parsen
│   │   │   ├── notes-adapter.go  # Schnittstelle zum Resource Server
│   │   │   ├── store_test.go     # Unit Tests für Login-State und Session-Token Storage
│   │   │   └── stores.go
│   │   ├── static                # statische Inhalte des Web Servers des Client 
│   │   │   ├── css
│   │   │   ├── img
│   │   │   └── js
│   │   └── templates            # die Notiz Seite wird mit Templates erstellt
│   │       ├── layout.html
│   │       └── notes.html
│   ├── data
│   │   └──postgres
│   │      └──pgdata
│   ├── init-db                    # Initialisierung der Datenbank für Resource Server
│   │   └──init.sql
│   ├── notes                      # Quellcode Resource Server
│   │   ├── certs                  # Zertifikate des Resource Server
│   │   ├── go.mod
│   │   ├── go.sum
│   │   ├── handlers.go            # CRUD Api des Resource Servers
│   │   ├── jwt_test.go            # Unit Tests für JWT validation
│   │   ├── main.go
│   │   └── utils.go
│   ├── client.Dockerfile          # Dockerfile des Client 
│   ├── notes.Dockerfile           # Dockerfile des Resource Server
│   ├── docker-compose.yaml        # Docker Compose für Client & Resource Server & Resource Server Datenbank
│   └── .gitignore 
│
├── docker-compose.yaml            # Docker Compose für Authentik Instanz
├── certs                          # Certificates für Authentik Instanz
├── custom-css                     # Custom CSS für Authentik Instanz
├── custom-templates               
├── media                          # Medien Dateien für Authentik Instanz (Hintergründe)
└── .env                           # Umgebungs Variablen für Authentik Instanz
```
