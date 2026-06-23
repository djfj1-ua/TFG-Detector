#!/usr/bin/env python3
"""
web/api.py — API REST para el detector de fraude académico.
Expone en JSON los dispositivos detectados por los scanners Wi-Fi y Bluetooth.

Requisitos:
  - wlan1 en modo monitor (sudo ./wlan1.sh monitor)
  - Ejecutar como root: sudo python3 web/api.py
  - Flask instalado: sudo apt install python3-flask

Endpoints:
  GET /api/status              — estado del sistema y contadores
  GET /api/devices             — todos los dispositivos activos (WiFi + BT)
  GET /api/devices/wifi        — solo dispositivos Wi-Fi activos
  GET /api/devices/bluetooth   — solo dispositivos Bluetooth activos
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify
from scanner.bluetooth import BluetoothScanner
from scanner.wifi_capture import WifiScanner

app = Flask(__name__)

_ACTIVE_WINDOW = 20.0   # segundos sin actividad para considerar un dispositivo inactivo
_start_time    = time.time()
_bt_scanner    = BluetoothScanner()
_wifi_scanner  = WifiScanner()


# ── Serialización ──────────────────────────────────────────────

def _wifi_to_dict(dev) -> dict:
    return {
        'mac':          dev.mac,
        'ssid':         dev.ssid,
        'rssi':         dev.rssi,
        'channel':      dev.channel,
        'frequency':    dev.frequency,
        'frame_type':   dev.frame_type,
        'manufacturer': dev.manufacturer,
        'proximity':    dev.proximity,
        'first_seen':   int(dev.first_seen),
        'last_seen':    int(dev.last_seen),
        'seconds_ago':  int(time.time() - dev.last_seen),
    }


def _bt_to_dict(dev) -> dict:
    return {
        'mac':             dev.mac,
        'name':            dev.name,
        'rssi':            dev.rssi,
        'bt_type':         dev.bt_type,
        'addr_type':       dev.addr_type,
        'manufacturer_id': dev.manufacturer_id,
        'uuids':           dev.uuids,
        'proximity':       dev.proximity,
        'first_seen':      int(dev.first_seen),
        'last_seen':       int(dev.last_seen),
        'seconds_ago':     int(time.time() - dev.last_seen),
    }


def _is_active(dev) -> bool:
    return (time.time() - dev.last_seen) <= _ACTIVE_WINDOW


def _bt_has_info(dev) -> bool:
    return bool(dev.name or dev.manufacturer_id is not None or dev.uuids)


# ── Endpoints ──────────────────────────────────────────────────

@app.route('/api/status')
def status():
    all_wifi = _wifi_scanner.devices
    all_bt   = _bt_scanner.devices
    return jsonify({
        'uptime':          int(time.time() - _start_time),
        'current_channel': _wifi_scanner.current_channel,
        'wifi': {
            'total':  len(all_wifi),
            'active': sum(1 for d in all_wifi if _is_active(d)),
        },
        'bluetooth': {
            'total':  len(all_bt),
            'active': sum(1 for d in all_bt if _is_active(d) and _bt_has_info(d)),
        },
    })


@app.route('/api/devices')
def devices():
    wifi = [_wifi_to_dict(d) for d in _wifi_scanner.devices if _is_active(d)]
    bt   = [_bt_to_dict(d)   for d in _bt_scanner.devices
            if _is_active(d) and _bt_has_info(d)]
    return jsonify({
        'wifi':      sorted(wifi, key=lambda d: d['rssi'] or -999, reverse=True),
        'bluetooth': sorted(bt,   key=lambda d: d['rssi'] or -999, reverse=True),
    })


@app.route('/api/devices/wifi')
def devices_wifi():
    devs = [_wifi_to_dict(d) for d in _wifi_scanner.devices if _is_active(d)]
    return jsonify(sorted(devs, key=lambda d: d['rssi'] or -999, reverse=True))


@app.route('/api/devices/bluetooth')
def devices_bluetooth():
    devs = [_bt_to_dict(d) for d in _bt_scanner.devices
            if _is_active(d) and _bt_has_info(d)]
    return jsonify(sorted(devs, key=lambda d: d['rssi'] or -999, reverse=True))


# ── Arranque ───────────────────────────────────────────────────

if __name__ == '__main__':
    if os.geteuid() != 0:
        print('Error: se requiere ejecutar como root (sudo).')
        sys.exit(1)

    _bt_scanner.start()
    _wifi_scanner.start()
    time.sleep(0.5)

    ip = os.popen("hostname -I | awk '{print $1}'").read().strip()
    print(f'Detectores arrancados. API disponible en:')
    print(f'  http://{ip}:5000/api/devices')
    print(f'  http://{ip}:5000/api/status')

    app.run(host='0.0.0.0', port=5000, debug=False)