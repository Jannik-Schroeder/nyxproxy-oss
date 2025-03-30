Planung: HTTPS-Proxy in Go

1️⃣ Ziel

Ein einfacher HTTPS-Proxy in Go, der Anfragen von Clients entgegennimmt und an einen Upstream-Server weiterleitet.

2️⃣ Anforderungen

HTTP(S)-Weiterleitung: Der Proxy nimmt Anfragen entgegen und leitet sie an den konfigurierten Upstream-Server weiter.

Nur ein Upstream-Server: Kein Load Balancing, nur eine Ziel-URL.

Kein Logging, kein Auth, kein Rate Limiting: Diese Features werden von einer Management-Ebene behandelt.

Einfach & performant: Keine unnötigen Abhängigkeiten, möglichst effizient.

3️⃣ Technologie-Stack

Programmiersprache: Go

Bibliotheken:

net/http → Standard HTTP-Handling

net/http/httputil → Reverse Proxy für Weiterleitung

4️⃣ Architektur

Proxy-Server startet auf Port 8080.

Client sendet HTTP(S)-Anfrage an localhost:8080.

Proxy leitet die Anfrage an den Upstream-Server weiter.

Die Antwort wird an den Client zurückgegeben.

5️⃣ Projektstruktur

https-proxy/
│── main.go  # Der Proxy-Server
│── go.mod   # Go-Moduldatei
│── README.md  # Projektbeschreibung

6️⃣ Umgebungsvariablen

Der Upstream-Server wird über eine Umgebungsvariable gesetzt:

HTTP_PROXY_UPSTREAM=https://example.com

7️⃣ Schritte zur Umsetzung

Go-Projekt initialisieren: go mod init https-proxy

HTTP-Proxy-Server schreiben: httputil.ReverseProxy nutzen.

Upstream-URL aus Umgebungsvariable laden.

Server starten und Anfragen weiterleiten.

Tests mit curl durchführen.

8️⃣ Beispiel-Aufruf

Starten des Proxys:

go run main.go

Testen mit curl:

curl -x http://localhost:8080 https://example.com

9️⃣ Erweiterungen (später)

TLS-Unterstützung (HTTPS auf dem Proxy selbst)

Fehlermanagement & Recovery-Mechanismen

Optimierung für hohe Last (z. B. Verbindungspooling)