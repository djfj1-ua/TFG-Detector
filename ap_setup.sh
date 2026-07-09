#!/bin/bash
# ap_setup.sh — Configura wlan0 como Access Point (hotspot) usando NetworkManager.
# Solo hay que ejecutarlo una vez. Después el AP arranca automáticamente al encender la Pi.
#
# Uso: sudo ./ap_setup.sh [ssid] [contraseña]
# Ejemplo: sudo ./ap_setup.sh DetectorFraude fraude2024
#
# Resultado:
#   - wlan0 → AP "DetectorFraude" con IP fija 10.42.0.1
#   - wlan1 → no gestionada por NetworkManager (libre para modo monitor)
#   - Flask API accesible en http://10.42.0.1:5000 desde el móvil

set -e

SSID="${1:-DetectorFraude}"
PASS="${2:-fraude2026}"
IFACE_AP="wlan0"
IFACE_SCAN="wlan1"

if [[ $EUID -ne 0 ]]; then
    echo "Error: ejecutar como root (sudo ./ap_setup.sh)"
    exit 1
fi

echo "=== Configurando Access Point en $IFACE_AP ==="
echo "  SSID       : $SSID"
echo "  Contraseña : $PASS"
echo "  IP del Pi  : 10.42.0.1"
echo ""

# ── Paso 1: Evitar que NetworkManager gestione wlan1 ──────────
# Así wlan1 queda libre para ponerla en modo monitor con iw/ip
CONF_DIR="/etc/NetworkManager/conf.d"
CONF_FILE="$CONF_DIR/unmanaged.conf"

mkdir -p "$CONF_DIR"
cat > "$CONF_FILE" <<EOF
[keyfile]
unmanaged-devices=interface-name:$IFACE_SCAN
EOF
echo "[1/5] wlan1 marcada como no gestionada por NetworkManager"

# ── Paso 2: Reiniciar NetworkManager para aplicar el cambio ──
systemctl restart NetworkManager
sleep 2
echo "[2/5] NetworkManager reiniciado"

# ── Paso 3: Captive portal — el móvil no debe creer que falta Internet ──
# El hotspot no necesita dar Internet real (el sistema no lo usa para
# nada), pero si el móvil detecta "sin Internet" en esta red puede
# desviar el tráfico de la app a datos móviles. Se redirige el DNS de
# los dominios que Android/iOS consultan para comprobar conectividad
# hacia la propia Pi; web/api.py responde esas peticiones en el :80.
DNSMASQ_DIR="/etc/NetworkManager/dnsmasq-shared.d"
mkdir -p "$DNSMASQ_DIR"
cat > "$DNSMASQ_DIR/captive.conf" <<EOF
address=/connectivitycheck.gstatic.com/10.42.0.1
address=/connectivitycheck.android.com/10.42.0.1
address=/clients3.google.com/10.42.0.1
address=/clients.l.google.com/10.42.0.1
address=/captive.apple.com/10.42.0.1
address=/www.apple.com/10.42.0.1
EOF
echo "[3/5] DNS del captive portal configurado"

# ── Paso 4: Crear el hotspot ──────────────────────────────────
# Si ya existe un perfil "Hotspot", lo borramos antes
nmcli connection delete "Hotspot" 2>/dev/null || true

nmcli dev wifi hotspot \
    ifname "$IFACE_AP" \
    ssid "$SSID" \
    password "$PASS"

echo "[4/5] Hotspot creado y activo"

# ── Paso 5: Autoconexión al arrancar ─────────────────────────
nmcli connection modify "Hotspot" \
    connection.autoconnect yes \
    connection.autoconnect-priority 100

echo "[5/5] Autoconexión configurada"

# ── Resultado ─────────────────────────────────────────────────
echo ""
echo "=== Configuración completada ==="
echo ""
echo "  Conecta el móvil a la red WiFi:"
echo "    Red        : $SSID"
echo "    Contraseña : $PASS"
echo ""
echo "  Luego inicia la API en la Raspberry:"
echo "    sudo ./wlan1.sh monitor"
echo "    sudo python3 web/api.py"
echo ""
echo "  IP de la API (ponla en la app): http://10.42.0.1:5000"
echo ""