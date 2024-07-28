# Microservices mit GO Projekt Fabian Schuller

## Übersicht

Das Projekt besteht aus einem OAuth Client (ein Webserver) und einem Resource Server mit Datenbankandbindung
Das Projekt benutzt eine Authentik Instanz (per Docker Compose) als OAuth Provider. 
Man muss einige Konfigurationen in der Benutzer-Oberfläche von Authentik vornehmen, deswegen wäre es praktisch direkt
auf dem Knoten zu testen. (sonst müsste man die Anwendung einrichten und Client Secret / Client Id im Quellcode anpassen)
Um das Projekt zu starten, muss man die beiden Docker Compose dateien ausführen. (falls noch nicht geschehen)

## OAuth Architektur

- Der Client führt den Authorization Code Flow aus, und speichert Access und Refresh Token unter einem SessionToken ab
- Im Browser wird dann ein Session Cookie gespeichert (und in die Website ein CSRF-Token eingebettet)
- Der "notes"-Scope wird in den Access Token (JWT) kodiert
- Der Client kann damit dann Anfragen an den Resource Server senden

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
│   │   │   ├── handlers.go
│   │   │   ├── main.go
│   │   │   ├── models.go
│   │   │   ├── notes-adapter.go  # Schnittstelle zum Resource Server
│   │   │   └── stores.go
│   │   ├── static                # für den Web Server des Client 
│   │   │   ├── css
│   │   │   ├── img
│   │   │   └── js
│   │   └── templates
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