#!/bin/bash
# service_setup.sh — Instala el servicio systemd del detector de fraude.
# Solo hay que ejecutarlo una vez.
# Uso: sudo ./service_setup.sh

set -e

if [[ $EUID -ne 0 ]]; then
    echo "Error: ejecutar como root (sudo ./service_setup.sh)"
    exit 1
fi

SERVICE="detector-fraude"
SERVICE_FILE="$(dirname "$(realpath "$0")")/$SERVICE.service"
TARGET="/etc/systemd/system/$SERVICE.service"

echo "=== Instalando servicio $SERVICE ==="

cp "$SERVICE_FILE" "$TARGET"
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

sleep 2
systemctl status "$SERVICE" --no-pager

echo ""
echo "=== Listo ==="
echo "La API arranca automáticamente al encender la Raspberry Pi."
echo ""
echo "Comandos útiles:"
echo "  sudo systemctl status  $SERVICE   # ver estado"
echo "  sudo systemctl restart $SERVICE   # reiniciar"
echo "  sudo journalctl -u $SERVICE -f    # ver logs en tiempo real"