#!/usr/bin/env python3
"""
web/api.py — API REST para el detector de fraude académico.
Expone en JSON los dispositivos detectados por los scanners Wi-Fi y Bluetooth.

Se gestiona como servicio systemd (detector-fraude.service) para arrancar
automáticamente con la Raspberry Pi. No requiere intervención manual.

Endpoints:
  POST /api/start — pone wlan1 en monitor y arranca los scanners
  POST /api/stop — detiene los scanners y restaura wlan1 a managed
  GET  /api/status — estado del sistema y contadores
  GET  /api/devices — todos los dispositivos activos (WiFi + BT)
  GET  /api/history — todos los dispositivos de la sesión (sin filtro)
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

_INTERFAZ = 'wlan1'
_VENTANA_ACTIVA = 20.0
_tiempo_inicio = time.time()
_bloqueo = threading.Lock()
_escaner_bt = None
_escaner_wifi = None
_escaneando = False


# ── Gestión del adaptador WiFi ─────────────────────────────────

def _activarModoMonitor() -> bool:
    """Pone wlan1 en modo monitor. Devuelve True si tiene éxito."""
    try:
        subprocess.run(['ip', 'link', 'set', _INTERFAZ, 'down'], check=True, capture_output=True)
        subprocess.run(['iw', 'dev', _INTERFAZ, 'set', 'type', 'monitor'], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', _INTERFAZ, 'up'], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f'Error al activar modo monitor: {e}', file=sys.stderr)
        return False


def _restaurarModoManaged() -> None:
    """Restaura wlan1 a modo managed."""
    try:
        subprocess.run(['ip', 'link', 'set', _INTERFAZ, 'down'], capture_output=True)
        subprocess.run(['iw', 'dev', _INTERFAZ, 'set', 'type', 'managed'], capture_output=True)
        subprocess.run(['ip', 'link', 'set', _INTERFAZ, 'up'], capture_output=True)
    except Exception:
        pass


# ── Control ────────────────────────────────────────────────────

@app.route('/api/start', methods=['POST'])
def iniciar():
    global _escaner_bt, _escaner_wifi, _escaneando, _tiempo_inicio
    with _bloqueo:
        if _escaneando:
            return jsonify({'ok': True, 'msg': 'Ya estaba escaneando'})

        if not _activarModoMonitor():
            return jsonify({'ok': False, 'msg': f'No se pudo poner {_INTERFAZ} en modo monitor'}), 500

        _escaner_bt = BluetoothScanner()
        _escaner_wifi = WifiScanner()
        _escaner_bt.start()
        _escaner_wifi.start()
        _escaneando = True
        _tiempo_inicio = time.time()
    return jsonify({'ok': True})


@app.route('/api/stop', methods=['POST'])
def detener():
    global _escaner_bt, _escaner_wifi, _escaneando
    with _bloqueo:
        if not _escaneando:
            return jsonify({'ok': True, 'msg': 'Ya estaba parado'})
        _escaner_bt.stop()
        _escaner_wifi.stop()
        _escaneando = False
    _restaurarModoManaged()
    return jsonify({'ok': True})


# ── Serialización ──────────────────────────────────────────────

def _wifiADict(dev) -> dict:
    return {
        'mac': dev.mac,
        'ssid': dev.ssid,
        'rssi': dev.rssi,
        'channel': dev.canal,
        'frequency': dev.frecuencia,
        'frame_type': dev.tipo_trama,
        'manufacturer': dev.fabricante,
        'proximity': dev.proximidad,
        'first_seen': int(dev.primera_vez),
        'last_seen': int(dev.ultima_vez),
        'seconds_ago': int(time.time() - dev.ultima_vez),
    }


def _btADict(dev) -> dict:
    return {
        'mac': dev.mac,
        'name': dev.nombre,
        'rssi': dev.rssi,
        'bt_type': dev.tipo,
        'proximity': dev.proximidad,
        'first_seen': int(dev.primera_vez),
        'last_seen': int(dev.ultima_vez),
        'seconds_ago': int(time.time() - dev.ultima_vez),
    }


def _esta_activo(dev) -> bool:
    return (time.time() - dev.ultima_vez) <= _VENTANA_ACTIVA


# ── Consulta ───────────────────────────────────────────────────

@app.route('/api/status')
def estado():
    with _bloqueo:
        escaneando = _escaneando
        escaner_bt = _escaner_bt
        escaner_wifi = _escaner_wifi

    total_wifi, activos_wifi, total_bt, activos_bt, canal = 0, 0, 0, 0, None
    if escaneando:
        todos_wifi = escaner_wifi.devices
        todos_bt = escaner_bt.devices
        total_wifi = len(todos_wifi)
        activos_wifi = sum(1 for d in todos_wifi if _esta_activo(d))
        total_bt = len(todos_bt)
        activos_bt = sum(1 for d in todos_bt  if _esta_activo(d))
        canal = escaner_wifi.canal_actual

    return jsonify({
        'scanning': escaneando,
        'uptime': int(time.time() - _tiempo_inicio),
        'current_channel': canal,
        'wifi': {'total': total_wifi, 'active': activos_wifi},
        'bluetooth': {'total': total_bt,   'active': activos_bt},
    })


@app.route('/api/devices')
def dispositivos():
    with _bloqueo:
        escaneando = _escaneando
        escaner_bt = _escaner_bt
        escaner_wifi = _escaner_wifi

    if not escaneando:
        return jsonify({'wifi': [], 'bluetooth': []})

    disp_wifi = [_wifiADict(d) for d in escaner_wifi.devices if _esta_activo(d)]
    disp_bt = [_btADict(d)   for d in escaner_bt.devices   if _esta_activo(d)]
    _rssi = lambda d: d['rssi'] if d['rssi'] is not None else -999
    return jsonify({
        'wifi':      sorted(disp_wifi, key=_rssi, reverse=True),
        'bluetooth': sorted(disp_bt,   key=_rssi, reverse=True),
    })


@app.route('/api/history')
def historial():
    """Todos los dispositivos vistos en la sesión, sin filtro de tiempo activo."""
    with _bloqueo:
        escaner_bt = _escaner_bt
        escaner_wifi = _escaner_wifi
        duracion = int(time.time() - _tiempo_inicio)

    if escaner_bt is None or escaner_wifi is None:
        return jsonify({'wifi': [], 'bluetooth': [], 'session_duration': 0})

    disp_wifi = [_wifiADict(d) for d in escaner_wifi.devices]
    disp_bt = [_btADict(d)   for d in escaner_bt.devices]
    _rssi = lambda d: d['rssi'] if d['rssi'] is not None else -999
    return jsonify({
        'wifi':             sorted(disp_wifi, key=_rssi, reverse=True),
        'bluetooth':        sorted(disp_bt,   key=_rssi, reverse=True),
        'session_duration': duracion,
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
app_cautiva = Flask(__name__ + '_cautiva')


@app_cautiva.route('/generate_204')
@app_cautiva.route('/gen_204')
def _verificacionAndroid():
    """Android espera HTTP 204 sin cuerpo para considerar que hay Internet."""
    return '', 204


@app_cautiva.route('/hotspot-detect.html')
@app_cautiva.route('/library/test/success.html')
def _verificacionApple():
    """iOS/macOS esperan este HTML exacto para considerar que hay Internet."""
    html = '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'
    return html, 200, {'Content-Type': 'text/html'}


def _lanzarPortalCautivo() -> None:
    """Lanza el servidor del captive portal en el puerto 80 (hilo daemon)."""
    try:
        app_cautiva.run(host='0.0.0.0', port=80, debug=False)
    except OSError as e:
        print(f'No se pudo iniciar el captive portal en :80: {e}', file=sys.stderr)


# ── Arranque ───────────────────────────────────────────────────

if __name__ == '__main__':
    if os.geteuid() != 0:
        print('Error: se requiere ejecutar como root (sudo).')
        sys.exit(1)

    ip_hotspot = os.popen("ip addr show wlan0 | awk '/inet /{print $2}' | cut -d/ -f1").read().strip()
    print(f'API disponible en:')
    if ip_hotspot:
        print(f'  Hotspot (móvil) → http://{ip_hotspot}:5000')
    print(f'  Scanners en reposo. La app arranca el escaneo.')

    threading.Thread(target=_lanzarPortalCautivo, daemon=True).start()

    app.run(host='0.0.0.0', port=5000, debug=False)
