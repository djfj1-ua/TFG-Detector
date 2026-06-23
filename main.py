#!/usr/bin/env python3
"""
main.py — Punto de entrada combinado del detector de fraude académico.
Ejecuta simultáneamente el scanner Bluetooth (BLE + Clásico) y el scanner
Wi-Fi 802.11, mostrando una vista unificada de todos los dispositivos detectados.

Requisitos:
  - wlan1 en modo monitor
  - Ejecutar como root (sudo python3 main.py)
"""

import os
import sys
import time
from typing import Optional

from scanner.bluetooth import BluetoothScanner
from scanner.wifi_capture import WifiScanner, _render_table, _signal_bar, _proximity_color

# ── Colores ANSI ──────────────────────────────────────────────
CYAN  = '\033[96m'
RESET = '\033[0m'
BOLD  = '\033[1m'
CLEAR = '\033[2J\033[H'

# Dispositivos sin actividad por más de este tiempo no se muestran en pantalla
_ACTIVE_WINDOW = 20.0


def _bt_info(dev) -> str:
    """Etiqueta identificativa para un BTDevice (nombre, fabricante o UUIDs)."""
    if dev.name:
        return dev.name[:26]
    if dev.manufacturer_id is not None:
        return f'MFR 0x{dev.manufacturer_id:04X}'
    if dev.uuids:
        return dev.uuids[0][:26]
    return '?'


def _render_bt_table(devices: list) -> str:
    lines = [
        f"{BOLD}{CYAN}{'TIPO':<8} {'MAC':<19} {'RSSI':>5}  {'SEÑAL':<10} "
        f"{'PROX':<12}  {'NOMBRE / FABRICANTE'}{RESET}",
        '─' * 82,
    ]
    for dev in sorted(devices, key=lambda d: d.rssi if d.rssi is not None else -999, reverse=True):
        color    = _proximity_color(dev.proximity)
        bar      = _signal_bar(dev.rssi)
        rssi_str = f'{dev.rssi:+4d}' if dev.rssi is not None else '  N/A'
        rnd      = ' [R]' if dev.addr_type == 'random' else ''
        age      = int(time.time() - dev.last_seen)
        info     = _bt_info(dev)
        lines.append(
            f"{color}{dev.bt_type:<8} {dev.mac:<19} {rssi_str}  {bar:<10} "
            f"{dev.proximity:<12}  {info}{rnd}  [{age}s]{RESET}"
        )
    return '\n'.join(lines)


def main() -> None:
    if os.geteuid() != 0:
        print('Error: se requiere ejecutar como root (sudo).')
        sys.exit(1)

    bt_scanner   = BluetoothScanner()
    wifi_scanner = WifiScanner()

    print('Iniciando detectores Bluetooth y Wi-Fi... (Ctrl+C para parar)')
    bt_scanner.start()
    wifi_scanner.start()
    time.sleep(0.5)

    start_time = time.time()

    try:
        while True:
            ahora   = time.time()
            elapsed = int(ahora - start_time)

            # Dispositivos activos en la ventana de tiempo
            bt_devs = [
                d for d in bt_scanner.devices
                if (d.name or d.manufacturer_id is not None or d.uuids)
                and (ahora - d.last_seen) <= _ACTIVE_WINDOW
            ]
            wifi_devs = [
                d for d in wifi_scanner.devices
                if (ahora - d.last_seen) <= _ACTIVE_WINDOW
            ]

            ch_str = (f'CH {wifi_scanner.current_channel}'
                      if wifi_scanner.current_channel else 'cambiando...')

            print(CLEAR, end='')
            print(f"{BOLD}=== TFG Detector Fraude Académico ==={RESET}")
            print(
                f"  Hora: {time.strftime('%H:%M:%S')}  |  "
                f"Activo: {elapsed}s  |  Ctrl+C para parar"
            )
            print()

            # ── Sección Wi-Fi ──────────────────────────────────
            print(
                f"{BOLD}── WI-FI  (wlan1 · {ch_str})  "
                f"{len(wifi_devs)} activos / {len(wifi_scanner.devices)} total{RESET}"
            )
            if wifi_devs:
                print(_render_table(wifi_devs))
            else:
                print('  Escuchando frames 802.11...')
            print()

            # ── Sección Bluetooth ──────────────────────────────
            print(
                f"{BOLD}── BLUETOOTH  "
                f"{len(bt_devs)} activos / {len(bt_scanner.devices)} total{RESET}"
            )
            if bt_devs:
                print(_render_bt_table(bt_devs))
            else:
                print('  Escuchando BLE y Bluetooth Clásico...')

            time.sleep(1.0)

    except KeyboardInterrupt:
        pass
    finally:
        bt_scanner.stop()
        wifi_scanner.stop()

        all_bt   = bt_scanner.devices
        all_wifi = wifi_scanner.devices

        print(f'\n{BOLD}Escaneo finalizado.{RESET}')
        print(f'  Bluetooth : {len(all_bt)} dispositivos detectados')
        print(f'  Wi-Fi     : {len(all_wifi)} dispositivos detectados')

        if all_bt:
            print(f'\n{BOLD}Bluetooth:{RESET}')
            for d in sorted(all_bt, key=lambda d: d.rssi or -999, reverse=True):
                rnd = ' [R]' if d.addr_type == 'random' else ''
                print(f'  {d.bt_type:<8} {d.mac}  RSSI={d.rssi}  '
                      f'PROX={d.proximity}  {_bt_info(d)}{rnd}')

        if all_wifi:
            print(f'\n{BOLD}Wi-Fi:{RESET}')
            for d in sorted(all_wifi, key=lambda d: d.rssi or -999, reverse=True):
                ssid = f'  SSID={d.ssid!r}' if d.ssid is not None else ''
                fab  = f'  {d.manufacturer}' if d.manufacturer else ''
                print(f'  {d.frame_type:<10} {d.mac}  RSSI={d.rssi}  '
                      f'PROX={d.proximity}  CH={d.channel}{fab}{ssid}')


if __name__ == '__main__':
    main()