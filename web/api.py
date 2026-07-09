#!/usr/bin/env python3
"""
web/api.py — API REST para el detector de fraude académico.
Expone en JSON los dispositivos detectados por los scanners Wi-Fi y Bluetooth.

Se gestiona como servicio systemd (detector-fraude.service) para arrancar
automáticamente con la Raspberry Pi. No requiere intervención manual.

Endpoints:
  POST /api/start    — pone wlan1 en monitor y arranca los scanners
  POST /api/stop     — detiene los scanners y restaura wlan1 a managed
  GET  /api/status   — estado del sistema y contadores
  GET  /api/devices  — todos los dispositivos activos (WiFi + BT)
  GET  /api/history  — todos los dispositivos de la sesión (sin filtro)
"""

import os
import sys
import time
import threading
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify
from scanner.bluetooth import BluetoothScanner
from scanner.wifi_capture import WifiScanner

app = Flask(__name__)

_IFACE       = 'wlan1'
_ACTIVE_WINDOW = 20.0
_start_time    = time.time()
_lock          = threading.Lock()
_bt_scanner    = None
_wifi_scanner  = None
_scanning      = False


# ── Gestión del adaptador WiFi ─────────────────────────────────

def _set_monitor_mode() -> bool:
    """Pone wlan1 en modo monitor. Devuelve True si tiene éxito."""
    try:
        subprocess.run(['ip', 'link', 'set', _IFACE, 'down'], check=True, capture_output=True)
        subprocess.run(['iw', 'dev', _IFACE, 'set', 'type', 'monitor'], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', _IFACE, 'up'], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f'Error al activar modo monitor: {e}', file=sys.stderr)
        return False


def _set_managed_mode() -> None:
    """Restaura wlan1 a modo managed."""
    try:
        subprocess.run(['ip', 'link', 'set', _IFACE, 'down'], capture_output=True)
        subprocess.run(['iw', 'dev', _IFACE, 'set', 'type', 'managed'], capture_output=True)
        subprocess.run(['ip', 'link', 'set', _IFACE, 'up'], capture_output=True)
    except Exception:
        pass


# ── Control ────────────────────────────────────────────────────

@app.route('/api/start', methods=['POST'])
def start():
    global _bt_scanner, _wifi_scanner, _scanning, _start_time
    with _lock:
        if _scanning:
            return jsonify({'ok': True, 'msg': 'Ya estaba escaneando'})

        if not _set_monitor_mode():
            return jsonify({'ok': False, 'msg': f'No se pudo poner {_IFACE} en modo monitor'}), 500

        _bt_scanner   = BluetoothScanner()
        _wifi_scanner = WifiScanner()
        _bt_scanner.start()
        _wifi_scanner.start()
        _scanning   = True
        _start_time = time.time()
    return jsonify({'ok': True})


@app.route('/api/stop', methods=['POST'])
def stop():
    global _bt_scanner, _wifi_scanner, _scanning
    with _lock:
        if not _scanning:
            return jsonify({'ok': True, 'msg': 'Ya estaba parado'})
        _bt_scanner.stop()
        _wifi_scanner.stop()
        _scanning = False
    _set_managed_mode()
    return jsonify({'ok': True})


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
        'mac':        dev.mac,
        'name':       dev.name,
        'rssi':       dev.rssi,
        'bt_type':    dev.bt_type,
        'proximity':  dev.proximity,
        'first_seen': int(dev.first_seen),
        'last_seen':  int(dev.last_seen),
        'seconds_ago': int(time.time() - dev.last_seen),
    }


def _is_active(dev) -> bool:
    return (time.time() - dev.last_seen) <= _ACTIVE_WINDOW



# ── Consulta ───────────────────────────────────────────────────

@app.route('/api/status')
def status():
    with _lock:
        scanning = _scanning
        bt  = _bt_scanner
        wf  = _wifi_scanner

    wifi_total, wifi_active, bt_total, bt_active, channel = 0, 0, 0, 0, None
    if scanning:
        all_wifi    = wf.devices
        all_bt      = bt.devices
        wifi_total  = len(all_wifi)
        wifi_active = sum(1 for d in all_wifi if _is_active(d))
        bt_total    = len(all_bt)
        bt_active   = sum(1 for d in all_bt if _is_active(d))
        channel     = wf.current_channel

    return jsonify({
        'scanning':        scanning,
        'uptime':          int(time.time() - _start_time),
        'current_channel': channel,
        'wifi':      {'total': wifi_total,  'active': wifi_active},
        'bluetooth': {'total': bt_total,    'active': bt_active},
    })


@app.route('/api/devices')
def devices():
    with _lock:
        scanning = _scanning
        bt  = _bt_scanner
        wf  = _wifi_scanner

    if not scanning:
        return jsonify({'wifi': [], 'bluetooth': []})

    wifi = [_wifi_to_dict(d) for d in wf.devices if _is_active(d)]
    bt_  = [_bt_to_dict(d)   for d in bt.devices if _is_active(d)]
    return jsonify({
        'wifi':      sorted(wifi, key=lambda d: d['rssi'], reverse=True),
        'bluetooth': sorted(bt_,  key=lambda d: d['rssi'], reverse=True),
    })



@app.route('/api/history')
def history():
    """Todos los dispositivos vistos en la sesión, sin filtro de tiempo activo."""
    with _lock:
        bt       = _bt_scanner
        wf       = _wifi_scanner
        duration = int(time.time() - _start_time)

    if bt is None or wf is None:
        return jsonify({'wifi': [], 'bluetooth': [], 'session_duration': 0})

    wifi = [_wifi_to_dict(d) for d in wf.devices]
    bt_  = [_bt_to_dict(d)   for d in bt.devices]
    return jsonify({
        'wifi':             sorted(wifi, key=lambda d: d['rssi'], reverse=True),
        'bluetooth':        sorted(bt_,  key=lambda d: d['rssi'], reverse=True),
        'session_duration': duration,
    })


# ── Captive portal ─────────────────────────────────────────────
# El hotspot de la Pi no tiene por qué dar Internet real a los móviles
# (el sistema no lo necesita para nada). Pero si un móvil detecta que
# una red Wi-Fi "no tiene Internet", muchos terminan desviando el
# tráfico de las apps a datos móviles aunque sigan conectados a esa
# red — rompiendo la conexión con esta API aunque el hotspot funcione
# perfectamente. Estas rutas responden exactamente lo que Android/iOS
# esperan en su comprobación de conectividad, para que el móvil crea
# que la red sí tiene Internet y mantenga el tráfico por Wi-Fi.
#
# El DNS de los dominios que el móvil consulta (connectivitycheck.
# gstatic.com, captive.apple.com, etc.) se redirige a la propia Pi
# mediante /etc/NetworkManager/dnsmasq-shared.d/captive.conf mientras
# que estas rutas, en el puerto 80, dan la respuesta que se espera.
captive_app = Flask(__name__ + '_captive')


@captive_app.route('/generate_204')
@captive_app.route('/gen_204')
def _android_connectivity_check():
    """Android espera HTTP 204 sin cuerpo para considerar que hay Internet."""
    return '', 204


@captive_app.route('/hotspot-detect.html')
@captive_app.route('/library/test/success.html')
def _apple_connectivity_check():
    """iOS/macOS esperan este HTML exacto para considerar que hay Internet."""
    html = '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'
    return html, 200, {'Content-Type': 'text/html'}


def _run_captive_portal() -> None:
    """Lanza el servidor del captive portal en el puerto 80 (hilo daemon)."""
    try:
        captive_app.run(host='0.0.0.0', port=80, debug=False)
    except OSError as e:
        print(f'No se pudo iniciar el captive portal en :80: {e}', file=sys.stderr)


# ── Arranque ───────────────────────────────────────────────────

if __name__ == '__main__':
    if os.geteuid() != 0:
        print('Error: se requiere ejecutar como root (sudo).')
        sys.exit(1)

    hotspot_ip = os.popen("ip addr show wlan0 | awk '/inet /{print $2}' | cut -d/ -f1").read().strip()
    print(f'API disponible en:')
    if hotspot_ip:
        print(f'  Hotspot (móvil) → http://{hotspot_ip}:5000')
    print(f'  Scanners en reposo. La app arranca el escaneo.')

    threading.Thread(target=_run_captive_portal, daemon=True).start()

    app.run(host='0.0.0.0', port=5000, debug=False)