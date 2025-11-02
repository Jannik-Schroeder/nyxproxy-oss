# NyxProxy IPv6 Rotation - Setup Anleitung (Deutsch)

## 🚀 Schnellstart (Debian/Ubuntu)

Die einfachste Methode für Debian/Ubuntu Server:

```bash
# 1. Als root einloggen oder sudo verwenden
sudo -i

# 2. Ins NyxProxy Verzeichnis wechseln
cd /pfad/zu/nyxproxy-core

# 3. Quick-Setup ausführen
chmod +x scripts/quick-setup.sh
./scripts/quick-setup.sh

# 4. NyxProxy bauen und starten
go build -o nyxproxy cmd/nyxproxy/main.go
./nyxproxy
```

Das war's! Der Script richtet alles automatisch ein:
- ✅ Erkennt automatisch dein Netzwerk-Interface
- ✅ Erkennt automatisch dein IPv6 Subnet
- ✅ Installiert und konfiguriert ndppd
- ✅ Erstellt config.yaml mit deinen Einstellungen
- ✅ Startet alle benötigten Services

---

## 📋 Manuelle Installation (Für Experten)

Falls du die Kontrolle über jeden Schritt haben möchtest:

### Schritt 1: System-Voraussetzungen prüfen

```bash
# IPv6 Konnektivität prüfen
ping6 -c 3 google.com

# Dein Interface und Subnet anzeigen
ip -6 addr show

# Beispiel Output:
# 2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP>
#     inet6 2a05:f480:1800:25db::1/64 scope global
```

### Schritt 2: ndppd Setup Script ausführen

```bash
cd scripts
chmod +x setup-ipv6-rotation.sh
sudo ./setup-ipv6-rotation.sh
```

Dieses Script:
1. Erkennt automatisch dein Interface (z.B. `ens3`, `eth0`)
2. Erkennt automatisch dein IPv6 /64 Subnet
3. Installiert ndppd (NDP Proxy Daemon)
4. Konfiguriert Kernel-Parameter
5. Erstellt eine config.yaml (falls nicht vorhanden)

### Schritt 3: Konfiguration überprüfen

Bearbeite `config.yaml`:

```yaml
network:
  interface_name: "ens3"        # Dein Interface (oder leer lassen für Auto-Erkennung)
  ipv4_enabled: false
  ipv6_enabled: true
  rotate_ipv6: true
  ipv6_subnet: "2a05:f480:1800:25db::/64"  # Dein Subnet
```

### Schritt 4: NyxProxy bauen und starten

```bash
# Zurück ins Hauptverzeichnis
cd ..

# Bauen
go build -o nyxproxy cmd/nyxproxy/main.go

# Starten
./nyxproxy
```

---

## ✅ Problemlösung

### Problem: "Cannot find device ''"

**Ursache:** Kein Interface-Name konfiguriert

**Lösung 1 (Automatisch):**
```bash
# Einfach den Proxy starten - Interface wird automatisch erkannt
./nyxproxy
```

Du siehst dann:
```
⚠️  WARNING: No interface specified, attempting auto-detection...
✓ Auto-detected interface: ens3
⚠️  For production use, please set 'interface_name: "ens3"' in config.yaml
```

**Lösung 2 (Manuell in config.yaml):**
```yaml
network:
  interface_name: "ens3"  # Dein Interface hier eintragen
```

**Interface herausfinden:**
```bash
ip -6 route | grep default | awk '{print $5}'
```

---

### Problem: "ndppd service is not running"

**Ursache:** ndppd Service läuft nicht

**Lösung:**
```bash
# ndppd installieren und konfigurieren
sudo ./scripts/setup-ipv6-rotation.sh

# Oder manuell starten
sudo systemctl start ndppd
sudo systemctl enable ndppd

# Status prüfen
systemctl status ndppd
```

---

### Problem: "failed to add IP ... exit status 1"

**Ursache:** Interface existiert nicht oder ist down

**Lösung:**
```bash
# Alle Interfaces anzeigen
ip link show

# Interface aktivieren (falls down)
sudo ip link set INTERFACE_NAME up

# Beispiel:
sudo ip link set ens3 up
```

---

### Problem: "No global IPv6 address found"

**Ursache:** Dein Server hat keine öffentliche IPv6-Adresse

**Lösung:**

1. **Überprüfe deine IPv6-Konfiguration beim Hosting-Provider**
   - Vultr: Network → Settings → IPv6
   - DigitalOcean: Networking → Add IPv6
   - Hetzner: Networking → IPv6 Subnets

2. **IPv6 auf dem Interface aktivieren:**
   ```bash
   # Interface-Konfiguration anzeigen
   cat /etc/network/interfaces

   # Für Debian/Ubuntu: IPv6 aktivieren
   sudo dhclient -6 ens3
   ```

3. **Überprüfen, ob IPv6 jetzt funktioniert:**
   ```bash
   ip -6 addr show
   ping6 google.com
   ```

---

## 🔍 Diagnose-Befehle

### ndppd Status prüfen
```bash
systemctl status ndppd
journalctl -u ndppd -n 50
```

### Interface und Subnets anzeigen
```bash
# Alle IPv6 Adressen
ip -6 addr show

# Routing-Tabelle
ip -6 route show

# Interface-Status
ip link show
```

### Proxy-Status prüfen
```bash
# Monitoring-Endpoint (falls aktiviert)
curl http://localhost:9090/stats

# Von außen testen
curl --proxy http://user:pass@YOUR_IP:8080 https://api6.ipify.org
```

### Test mit verschiedenen IPv6-Adressen
```bash
# 3x hintereinander - sollte 3 verschiedene IPs zeigen
for i in {1..3}; do
  curl --proxy http://user:pass@YOUR_IP:8080 https://api6.ipify.org
  echo
done
```

---

## ⚙️ Erweiterte Konfiguration

### Auto-Erkennung vs. Manuelle Konfiguration

**Auto-Erkennung (Standard):**
```yaml
network:
  interface_name: ""  # Leer = automatisch
  rotate_ipv6: true
  ipv6_subnet: "2a05:f480:1800:25db::/64"
```

**Manuelle Konfiguration (Produktion empfohlen):**
```yaml
network:
  interface_name: "ens3"  # Explizit angeben
  rotate_ipv6: true
  ipv6_subnet: "2a05:f480:1800:25db::/64"
```

### Mehrere Proxies auf einem Server

Wenn du mehrere Proxy-Instanzen betreiben möchtest:

```yaml
# Proxy 1 (Port 8080)
proxy:
  listen_port: 8080

# Proxy 2 (Port 8081) - separate config.yaml
proxy:
  listen_port: 8081
```

ndppd muss nur einmal laufen und verarbeitet alle Proxies.

---

## 📊 Systemanforderungen

- **OS:** Linux (Debian, Ubuntu, CentOS, etc.)
- **Kernel:** >= 3.10 (mit IPv6-Support)
- **RAM:** >= 512 MB
- **IPv6:** Routed /64 Subnet erforderlich
- **Rechte:** Root-Zugriff für Setup (ndppd, sysctl)

---

## 🎯 Häufige Szenarien

### Szenario 1: Frischer Debian Server (Vultr, DigitalOcean, etc.)

```bash
# 1. Als root einloggen
ssh root@your-server

# 2. Go installieren (falls nicht vorhanden)
apt update
apt install -y golang-go git

# 3. NyxProxy klonen
git clone https://github.com/yourusername/nyxproxy-core.git
cd nyxproxy-core

# 4. Quick-Setup
chmod +x scripts/quick-setup.sh
./scripts/quick-setup.sh

# 5. Bauen und starten
go build -o nyxproxy cmd/nyxproxy/main.go
./nyxproxy
```

### Szenario 2: Bereits laufender Server mit Config

```bash
# 1. Setup nur für ndppd
sudo ./scripts/setup-ipv6-rotation.sh

# 2. Bestehende config.yaml anpassen
vi config.yaml
# interface_name und ipv6_subnet eintragen

# 3. Proxy starten
./nyxproxy
```

### Szenario 3: Debugging / Testumgebung

```bash
# 1. Debug-Logging aktivieren
vi config.yaml
# logging.debug_level: 2

# 2. Monitoring aktivieren
# monitoring.enabled: true

# 3. Proxy starten und Logs beobachten
./nyxproxy

# In anderem Terminal:
journalctl -u ndppd -f  # ndppd Logs
curl http://localhost:9090/stats  # Proxy Stats
```

---

## 🆘 Support

Bei Problemen:

1. **Logs prüfen:**
   ```bash
   # ndppd Logs
   journalctl -u ndppd -n 100

   # Kernel Messages
   dmesg | grep -i ipv6
   ```

2. **System-Info sammeln:**
   ```bash
   # Interface Info
   ip -6 addr show > debug-info.txt
   ip -6 route show >> debug-info.txt

   # ndppd Status
   systemctl status ndppd >> debug-info.txt

   # Kernel Parameter
   sysctl -a | grep ipv6 >> debug-info.txt
   ```

3. **GitHub Issue erstellen** mit debug-info.txt

---

## ✨ Tipps & Best Practices

1. **Immer interface_name in config.yaml setzen** (Produktion)
2. **ndppd Status regelmäßig prüfen** (Monitoring)
3. **Logs rotieren** (logrotate für große Log-Dateien)
4. **Firewall-Regeln anpassen** (Port 8080 öffnen)
5. **Systemd Service erstellen** (Auto-Start nach Reboot)

### Systemd Service Beispiel

```bash
cat > /etc/systemd/system/nyxproxy.service <<EOF
[Unit]
Description=NyxProxy IPv6 Rotating Proxy
After=network.target ndppd.service
Requires=ndppd.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/nyxproxy-core
ExecStart=/root/nyxproxy-core/nyxproxy
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nyxproxy
systemctl start nyxproxy
```

---

**Viel Erfolg mit NyxProxy! 🚀**
