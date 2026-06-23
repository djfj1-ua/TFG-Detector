#!/bin/bash
if [[ "$1" != "monitor" && "$1" != "managed" ]]; then
    echo "Uso: sudo $0 [monitor|managed]"
    exit 1
fi

ip link set wlan1 down
iw dev wlan1 set type "$1"
ip link set wlan1 up
iw dev wlan1 info