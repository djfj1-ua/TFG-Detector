#!/usr/bin/env python3
"""
wifi_capture.py — Scanner Wi-Fi 802.11 en modo monitor para TFG detección fraude académico.
Raspberry Pi 5, Alfa AWUS036ACHM (MT7612U), Raspberry Pi OS Bookworm ARM64.
Sin dependencias externas. Sockets AF_PACKET RAW únicamente.

La interfaz wlan1 debe estar en modo monitor antes de ejecutar el script.
"""

import itertools
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────────────────────
# CONSTANTES 802.11
# ──────────────────────────────────────────────────────────────

TIPO_TRAMA_DATOS = 0x02  # Data: tráfico de usuario (se descartan gestión y control)


# ──────────────────────────────────────────────────────────────
# BASE DE DATOS OUI → FABRICANTE
# ──────────────────────────────────────────────────────────────

# Rutas donde buscar el fichero IEEE OUI.
# Para instalar la base completa (~6 MB, >50.000 entradas):
#   sudo apt install ieee-data  →  /usr/share/ieee-data/oui.txt
_RUTAS_OUI = (
    '/usr/share/ieee-data/oui.txt',
    '/usr/share/misc/oui.txt',
    'scanner/oui.txt',
    'oui.txt',
)

_OUI_RESERVA: dict = {
    # Apple
    '000393': 'Apple', '000A95': 'Apple', '001124': 'Apple', '001451': 'Apple',
    '001E52': 'Apple', '001EC2': 'Apple', '002241': 'Apple', '002312': 'Apple',
    '0025BC': 'Apple', '34C059': 'Apple', '3C0754': 'Apple', '4C8D79': 'Apple',
    '70DEE2': 'Apple', 'A4C361': 'Apple', 'BC926B': 'Apple', 'DC2B61': 'Apple',
    'F0272D': 'Apple', 'F4F951': 'Apple', 'F8FFC2': 'Apple',
    # Samsung
    '002339': 'Samsung', '08ECD3': 'Samsung', '3C8BFE': 'Samsung',
    '5CF370': 'Samsung', '8C77B9': 'Samsung', 'B47C9C': 'Samsung',
    'C869CD': 'Samsung', 'F4428F': 'Samsung',
    # Xiaomi / Redmi / POCO
    '0CFB43': 'Xiaomi', '28E31F': 'Xiaomi', '64B473': 'Xiaomi',
    '7C1DD9': 'Xiaomi', '9C99A0': 'Xiaomi', 'DC9758': 'Xiaomi',
    # Huawei / Honor
    '001E10': 'Huawei', '286ED4': 'Huawei', '40CBFD': 'Huawei',
    '6C8D6F': 'Huawei', 'B4430D': 'Huawei', 'D4F5EF': 'Huawei',
    # Google — Pixel
    '3C5AB4': 'Google', 'A47C5A': 'Google', 'F488E2': 'Google',
    # OnePlus / OPPO / Realme
    '001A7D': 'OPPO', '94652D': 'OnePlus', 'AC8766': 'OPPO',
    # Motorola
    '00125A': 'Motorola', '98D29B': 'Motorola', 'BC776C': 'Motorola',
    # Sony
    '0013A9': 'Sony', '30170F': 'Sony', '9844CF': 'Sony',
    # LG
    '001E75': 'LG', '20F301': 'LG', '88C9D0': 'LG',
    # Raspberry Pi
    'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',
}


def _cargarOUI() -> dict:
    """
    Carga la base de datos OUI desde el fichero IEEE si está disponible.
    Si no encuentra ningún fichero válido, devuelve _OUI_RESERVA.
    """
    for ruta in _RUTAS_OUI:
        try:
            base: dict = {}
            with open(ruta, encoding='utf-8', errors='replace') as fh:
                for linea in fh:
                    if '(hex)' not in linea:
                        continue
                    partes = linea.split('(hex)')
                    if len(partes) < 2:
                        continue
                    oui = partes[0].strip().replace('-', '').upper()
                    if len(oui) != 6:
                        continue
                    nombre = partes[1].strip()
                    if nombre:
                        base[oui] = nombre
            if base:
                return base
        except OSError:
            continue
    return _OUI_RESERVA


_BASE_OUI: dict = _cargarOUI()


def _buscarFabricante(mac: str) -> Optional[str]:
    """Devuelve el fabricante a partir de los primeros 3 bytes del MAC, o None si no está."""
    oui = mac[:8].replace(':', '').upper()
    return _BASE_OUI.get(oui)


# ──────────────────────────────────────────────────────────────
# PARSEO RADIOTAP
# ──────────────────────────────────────────────────────────────

# Campos RadioTap en orden de bit: (bit_en_present, tamaño_bytes, alineación_bytes)
# Alineación medida desde el byte 0 del header RadioTap.
# Fuente: https://www.radiotap.org/fields/
_CAMPOS_RT = (
    (0,  8, 8),  # TSFT
    (1,  1, 1),  # Flags         — bit 4 = FCS presente al final del frame
    (2,  1, 1),  # Rate
    (3,  4, 2),  # Channel       — 2 bytes frecuencia MHz + 2 bytes flags
    (4,  2, 1),  # FHSS
    (5,  1, 1),  # dBm Ant Sig   — RSSI en dBm (int8 signed)
    (6,  1, 1),  # dBm Ant Noise
    (7,  2, 2),  # Lock Quality
    (8,  2, 2),  # TX Attenuation
    (9,  2, 2),  # dB TX Attenuation
    (10, 1, 1),  # dBm TX Power
    (11, 1, 1),  # Antenna
    (12, 1, 1),  # dB Ant Signal
    (13, 1, 1),  # dB Ant Noise
    (14, 2, 2),  # RX Flags
    (15, 2, 2),  # TX Flags
    (16, 1, 1),  # RTS Retries
    (17, 1, 1),  # Data Retries
)

INTERFAZ_MONITOR  = 'wlan1'
ETH_P_ALL         = 0x0003  # recibe todos los frames de la capa de enlace

_CANALES_2GHZ: list       = list(range(1, 14))
INTERVALO_SALTO: float    = 0.20  # segundos por canal; barrido completo = 13 × 0.2 = 2.6s


# ──────────────────────────────────────────────────────────────
# MODELO DE DATOS
# ──────────────────────────────────────────────────────────────

@dataclass
class DispositivoWifi:
    """Representa un dispositivo Wi-Fi detectado por su dirección transmisora (addr2)."""
    mac:        str            # dirección MAC transmisora (addr2)
    ssid:       Optional[str]  # SSID de la red a la que está conectado
    rssi:       Optional[int]  # potencia de señal en dBm
    canal:      Optional[int]  # canal 802.11 (1-13 en 2.4 GHz)
    frecuencia: Optional[int]  # frecuencia en MHz
    tipo_trama: str            # tipo del último frame recibido
    fabricante: Optional[str]  # fabricante según OUI; None si desconocido
    primera_vez: float = field(default_factory=time.time)
    ultima_vez:  float = field(default_factory=time.time)

    @property
    def proximidad(self) -> str:
        if self.rssi is None:
            return 'desconocido'
        if self.rssi >= -70:
            return 'cerca'
        if self.rssi >= -85:
            return 'dentro del aula'
        return 'fuera'


# ──────────────────────────────────────────────────────────────
# PARSEO RADIOTAP
# ──────────────────────────────────────────────────────────────

def _parsearRadiotap(raw: bytes) -> dict:
    """
    Parsea el header RadioTap que el driver antepone a cada frame 802.11 capturado.

    Estructura:
      [0]   revision = 0
      [1]   pad = 0
      [2:4] longitud total del header (LE)
      [4:8] present — bitmask con los campos presentes; bit 31 = sigue otra palabra

    Devuelve: long_cab, rssi, frecuencia, canal, fcs_presente
    """
    resultado: dict = {
        'long_cab':     0,
        'rssi':         None,
        'frecuencia':   None,
        'canal':        None,
        'fcs_presente': False,
    }

    if len(raw) < 8:
        return resultado

    long_cab = struct.unpack_from('<H', raw, 2)[0]
    resultado['long_cab'] = min(long_cab, len(raw))

    present = struct.unpack_from('<I', raw, 4)[0]

    offset = 4
    while True:
        w = struct.unpack_from('<I', raw, offset)[0]
        offset += 4
        if not (w & (1 << 31)):
            break

    for bit, size, align in _CAMPOS_RT:
        if not (present & (1 << bit)):
            continue

        if align > 1 and (offset % align) != 0:
            offset += align - (offset % align)

        if offset + size > resultado['long_cab']:
            break

        if bit == 1:  # Flags: bit 4 indica FCS al final del frame
            resultado['fcs_presente'] = bool(raw[offset] & 0x10)

        elif bit == 3:  # Channel: 2 bytes frecuencia MHz + 2 bytes flags
            freq = struct.unpack_from('<H', raw, offset)[0]
            resultado['frecuencia'] = freq
            if 2412 <= freq <= 2472:
                resultado['canal'] = (freq - 2407) // 5
            elif freq == 2484:
                resultado['canal'] = 14
            elif 5180 <= freq <= 5825:
                resultado['canal'] = (freq - 5000) // 5

        elif bit == 5:  # dBm Antenna Signal: RSSI en dBm (int8 signed)
            resultado['rssi'] = struct.unpack_from('b', raw, offset)[0]

        offset += size

    return resultado


# ──────────────────────────────────────────────────────────────
# PARSEO CABECERA 802.11
# ──────────────────────────────────────────────────────────────

def _formatearMAC(raw6: bytes) -> str:
    """Convierte 6 bytes de dirección MAC a la cadena XX:XX:XX:XX:XX:XX en mayúsculas."""
    return ':'.join(f'{b:02X}' for b in raw6)


def _esUnicast(raw6: bytes) -> bool:
    """El bit 0 del primer octeto a 0 indica dirección unicast."""
    return not (raw6[0] & 0x01)


def _parsearCabecera(trama: bytes) -> Optional[dict]:
    """
    Parsea la cabecera MAC 802.11 de un frame DATA.

    Frame Control (2 bytes):
      Byte 0 bits 2-3 — Type: 0x02 = Data
      Byte 1 bit 0    — ToDS, bit 1 — FromDS

    Addr2 (bytes 10-15) es siempre el transmisor del frame.
    Devuelve None si no es DATA o si el frame es demasiado corto.
    """
    if len(trama) < 24:
        return None

    fc0 = trama[0]
    fc1 = trama[1]

    tipo    = (fc0 >> 2) & 0x03
    from_ds = (fc1 >> 1) & 0x01

    if tipo != TIPO_TRAMA_DATOS:
        return None

    addr2_raw = trama[10:16]

    return {
        'from_ds':   from_ds,
        'addr2':     _formatearMAC(addr2_raw),
        'addr2_raw': addr2_raw,
    }


# ──────────────────────────────────────────────────────────────
# CHANNEL HOPPING
# ──────────────────────────────────────────────────────────────

def _cambiarCanal(interfaz: str, canal: int) -> bool:
    """
    Cambia el canal de la interfaz Wi-Fi usando 'iw'.
    Devuelve True si el cambio se realizó con éxito.
    """
    try:
        resultado = subprocess.run(
            ['iw', 'dev', interfaz, 'set', 'channel', str(canal)],
            capture_output=True,
            timeout=2,
        )
        return resultado.returncode == 0
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────
# SCANNER PRINCIPAL
# ──────────────────────────────────────────────────────────────

class WifiScanner:
    """
    Scanner Wi-Fi 802.11 pasivo en modo monitor.
    Captura tramas de datos sobre wlan1 (Alfa AWUS036ACHM) sin inyectar nada.
    """

    def __init__(self, interfaz: str = INTERFAZ_MONITOR,
                 intervalo: float = INTERVALO_SALTO):
        self._interfaz  = interfaz
        self._intervalo = intervalo

        self._vistos: dict[str, DispositivoWifi] = {}
        self._bloqueo = threading.Lock()
        self._activo  = threading.Event()

        self._hilo_captura: Optional[threading.Thread] = None
        self._hilo_salto:   Optional[threading.Thread] = None

        self.canal_actual: Optional[int] = None

    # ── API pública ────────────────────────────────────────────

    def start(self) -> None:
        self._activo.set()
        self._hilo_captura = threading.Thread(
            target=self._bucleCaptura, daemon=True, name='wifi-cap'
        )
        self._hilo_salto = threading.Thread(
            target=self._bucleCanales, daemon=True, name='wifi-hop'
        )
        self._hilo_captura.start()
        self._hilo_salto.start()

    def stop(self) -> None:
        self._activo.clear()

    @property
    def devices(self) -> list:
        with self._bloqueo:
            return list(self._vistos.values())

    # ── Hilo de captura ────────────────────────────────────────

    def _bucleCaptura(self) -> None:
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
            )
            sock.bind((self._interfaz, 0))
            sock.settimeout(1.0)
        except OSError as e:
            print(f'[wifi] Error al abrir socket en {self._interfaz}: {e}', file=sys.stderr)
            return

        try:
            while self._activo.is_set():
                try:
                    raw = sock.recv(4096)
                except Exception:
                    continue
                self._procesarTrama(raw)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── Channel hopping ───────────────────────────────────────

    def _bucleCanales(self) -> None:
        for canal in itertools.cycle(_CANALES_2GHZ):
            if not self._activo.is_set():
                break

            if _cambiarCanal(self._interfaz, canal):
                self.canal_actual = canal

            limite = time.monotonic() + self._intervalo
            while self._activo.is_set() and time.monotonic() < limite:
                time.sleep(0.05)

    # ── Procesado de tramas ────────────────────────────────────

    def _procesarTrama(self, raw: bytes) -> None:
        """
        Flujo de procesado:
          1. Parsea el header RadioTap → RSSI, canal, frecuencia
          2. Descarta si no es frame DATA
          3. Descarta si from_ds=1 (AP→cliente)
          4. Descarta si addr2 no es unicast
          5. Registra o actualiza el dispositivo
        """
        rt       = _parsearRadiotap(raw)
        long_cab = rt['long_cab']
        if long_cab >= len(raw):
            return

        recorte_fcs = 4 if rt['fcs_presente'] else 0
        trama       = raw[long_cab: len(raw) - recorte_fcs]

        cabecera = _parsearCabecera(trama)
        if cabecera is None:
            return

        if cabecera['from_ds'] == 1:
            return

        if not _esUnicast(cabecera['addr2_raw']):
            return

        informe = {
            'mac':        cabecera['addr2'],
            'ssid':       None,
            'rssi':       rt.get('rssi'),
            'canal':      rt.get('canal'),
            'frecuencia': rt.get('frecuencia'),
            'tipo_trama': 'DATA',
        }
        self._registrarDispositivo(informe)

    # ── Registro de dispositivos ───────────────────────────────

    def _registrarDispositivo(self, informe: dict) -> None:
        mac   = informe['mac']
        ahora = time.time()

        with self._bloqueo:
            if mac in self._vistos:
                disp            = self._vistos[mac]
                disp.ultima_vez = ahora
                disp.tipo_trama = informe['tipo_trama']
                if informe['rssi'] is not None:
                    disp.rssi = informe['rssi']
                if informe['ssid'] is not None:
                    disp.ssid = informe['ssid']
                if informe['canal'] is not None:
                    disp.canal = informe['canal']
                if informe['frecuencia'] is not None:
                    disp.frecuencia = informe['frecuencia']
            else:
                self._vistos[mac] = DispositivoWifi(
                    mac=mac,
                    ssid=informe['ssid'],
                    rssi=informe['rssi'],
                    canal=informe['canal'],
                    frecuencia=informe['frecuencia'],
                    tipo_trama=informe['tipo_trama'],
                    fabricante=_buscarFabricante(mac),
                    primera_vez=ahora,
                    ultima_vez=ahora,
                )
