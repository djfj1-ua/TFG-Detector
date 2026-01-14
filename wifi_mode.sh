#!/bin/bash

INTERFAZ="wlp4s0"

if [ "$EUID" -ne 0 ]; then
	echo "Por favor, ejecuta el script como root."
	exit
fi

case "$1" in monitor)
	echo "Activando MODO MONITOR en $INTERFAZ..."
	#1. Elimina los procesos activos
	airmon-ng check kill
	#2. Activa la interfac con airmon-ng
	airmon-ng start $INTERFAZ
	#3. Forzar estado si no funciona airmon-ng
	ip link set $INTERFAZ up
	echo "-----------------------------"
	iwconfig | grep -A 1 $INTERFAZ
	echo "Listo. Interfaz actual: $INTERFAZ"
	;;
	managed)
	echo "Restaurando MODO MANAGED en $INTERFAZ"
	#1. Detener modo monitor
	airmon-ng stop $INTERFAZ
	#2. Forzar limpieza manual
	ip link set $INTERFAZ down
	iw $INTERFAZ set type managed
	ip link set $INTERFAZ up
	#3. Reiniciar NetworkManager
	systemctl restart NetworkManager
	echo "-----------------------------"
	iwconfig | grep -A 1 $INTERFAZ
	echo "Sistema modo managed."
	;;
	*)
	echo "Uso: sudo $0 {monitor|managed}"
	exit 1
	;;
esac
