#!/usr/bin/env python3
"""
wifi_capture.py — Scanner Wi-Fi 802.11 en modo monitor para TFG detección fraude académico.
Raspberry Pi 5, Alfa AWUS036ACHM (MT7612U), Raspberry Pi OS Bookworm ARM64.
Sin dependencias externas. Sockets AF_PACKET RAW únicamente.

La interfaz wlan1 debe estar en modo monitor antes de ejecutar el script.
"""

import itertools
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


# ──────────────────────────────────────────────────────────────
# CONSTANTES 802.11
# ──────────────────────────────────────────────────────────────

# Tipos de frame 802.11 (bits 2-3 del byte 0 del Frame Control)
FRAME_TYPE_MGMT = 0x00   # Management: Beacon, Probe, Auth, Assoc
FRAME_TYPE_CTRL = 0x01   # Control: ACK, RTS, CTS  (se ignoran)
FRAME_TYPE_DATA = 0x02   # Data: tráfico de usuario (se ignoran)

# Subtipos de frames de gestión (bits 4-7 del byte 0 del Frame Control)
# Solo los relevantes para detección de fraude académico
SUBTYPE_ASSOC_REQ  = 0x00   # Association Request  — dispositivo intentando unirse a una red
SUBTYPE_ASSOC_RESP = 0x01   # Association Response — AP aceptando o rechazando la asociación
SUBTYPE_PROBE_REQ  = 0x04   # Probe Request        — dispositivo buscando redes activamente
SUBTYPE_PROBE_RESP = 0x05   # Probe Response       — AP respondiendo a un Probe Request
SUBTYPE_BEACON     = 0x08   # Beacon               — AP anunciando su red periódicamente
SUBTYPE_AUTH       = 0x0B   # Authentication       — inicio del handshake de autenticación
SUBTYPE_DEAUTH     = 0x0C   # Deauthentication     — cierre de sesión forzado

# Mapa subtype → nombre legible para mostrar en pantalla
SUBTYPE_NAMES = {
    SUBTYPE_ASSOC_REQ:  'ASSOC_REQ',
    SUBTYPE_ASSOC_RESP: 'ASSOC_RESP',
    SUBTYPE_PROBE_REQ:  'PROBE_REQ',
    SUBTYPE_PROBE_RESP: 'PROBE_RESP',
    SUBTYPE_BEACON:     'BEACON',
    SUBTYPE_AUTH:       'AUTH',
    SUBTYPE_DEAUTH:     'DEAUTH',
}

# Bytes de campos fijos que preceden a los IEs en cada subtipo de Management frame.
# Los 24 bytes de cabecera MAC son comunes a todos; estos son los bytes ADICIONALES
# específicos de cada subtipo antes de que empiecen los Information Elements.
#
# Subtype → fixed fields size (bytes)
#   ASSOC_REQ  (0x00): Capability(2) + Listen Interval(2)               = 4
#   ASSOC_RESP (0x01): Capability(2) + Status Code(2) + Assoc ID(2)     = 6
#   PROBE_REQ  (0x04): sin campos fijos, IEs empiezan de inmediato       = 0
#   PROBE_RESP (0x05): Timestamp(8) + Beacon Interval(2) + Capability(2) = 12
#   BEACON     (0x08): Timestamp(8) + Beacon Interval(2) + Capability(2) = 12
#   AUTH       (0x0B): Algorithm(2) + Auth Seq(2) + Status Code(2)      = 6
#   DEAUTH     (0x0C): Reason Code(2)                                    = 2
_FIXED_FIELDS_SIZE = {
    SUBTYPE_ASSOC_REQ:  4,
    SUBTYPE_ASSOC_RESP: 6,
    SUBTYPE_PROBE_REQ:  0,
    SUBTYPE_PROBE_RESP: 12,
    SUBTYPE_BEACON:     12,
    SUBTYPE_AUTH:       6,
    SUBTYPE_DEAUTH:     2,
}

# Tags de Information Elements (IEs) — formato TLV compartido por todos los Mgmt frames
IE_SSID     = 0x00   # SSID del AP o de la red buscada (Probe Request wildcard si len=0)
IE_DS_PARAM = 0x03   # DS Parameter Set: canal actual del AP (1 byte sin signo)
IE_RSN      = 0x30   # Robust Security Network → WPA2 / WPA3
IE_VENDOR   = 0xDD   # Vendor Specific: puede contener WPA Information Element (Microsoft)

# OUI de Microsoft + tipo 0x01: identifica el WPA IE anterior a RSN (WPA1)
_MS_OUI_WPA = b'\x00\x50\xf2\x01'


# ──────────────────────────────────────────────────────────────
# BASE DE DATOS OUI → FABRICANTE
# ──────────────────────────────────────────────────────────────

# Rutas donde buscar el fichero IEEE OUI (formato estándar IEEE).
# Para instalar la base completa (~6 MB, >50.000 entradas):
#   sudo apt install ieee-data          →  /usr/share/ieee-data/oui.txt
# O descargar manualmente:
#   wget -O scanner/oui.txt https://standards-oui.ieee.org/oui/oui.txt
_OUI_FILE_PATHS = (
    '/usr/share/ieee-data/oui.txt',
    '/usr/share/misc/oui.txt',
    'scanner/oui.txt',
    'oui.txt',
)

# Tabla de reserva mínima para cuando no hay fichero IEEE disponible.
# Clave: 6 hex chars sin separadores, mayúsculas (primeros 3 bytes del MAC).
# Cubre solo las marcas más frecuentes en un aula universitaria española.
_OUI_FALLBACK: dict = {
    # Apple — docenas de OUIs; estos cubren iPhones y MacBooks recientes
    '000393': 'Apple', '000A95': 'Apple', '001124': 'Apple', '001451': 'Apple',
    '001E52': 'Apple', '001EC2': 'Apple', '002241': 'Apple', '002312': 'Apple',
    '0025BC': 'Apple', '34C059': 'Apple', '3C0754': 'Apple', '4C8D79': 'Apple',
    '70DEE2': 'Apple', 'A4C361': 'Apple', 'BC926B': 'Apple', 'DC2B61': 'Apple',
    'F0272D': 'Apple', 'F4F951': 'Apple', 'F8FFC2': 'Apple',
    # Samsung — smartphones Galaxy y tablets
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
    # OnePlus / OPPO / Realme (mismo grupo BBK)
    '001A7D': 'OPPO',   '94652D': 'OnePlus', 'AC8766': 'OPPO',
    # Motorola
    '00125A': 'Motorola', '98D29B': 'Motorola', 'BC776C': 'Motorola',
    # Sony
    '0013A9': 'Sony', '30170F': 'Sony', '9844CF': 'Sony',
    # LG Electronics
    '001E75': 'LG',  '20F301': 'LG',  '88C9D0': 'LG',
    # Raspberry Pi Foundation (la propia Pi aparece a veces)
    'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',
}


def _load_oui_db() -> dict:
    """
    Carga la base de datos OUI desde el fichero IEEE si está disponible.

    Formato de las líneas de interés en el fichero IEEE oui.txt:
      XX-XX-XX   (hex)\t\tManufacturer Name
    Ejemplo:
      DC-97-58   (hex)\t\tXiaomi Communications Co Ltd

    Si no encuentra ningún fichero válido, devuelve la tabla _OUI_FALLBACK.
    Se llama una sola vez al importar el módulo; el resultado se guarda en _OUI_DB.
    """
    for path in _OUI_FILE_PATHS:
        try:
            db: dict = {}
            with open(path, encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    if '(hex)' not in line:
                        continue
                    parts = line.split('(hex)')
                    if len(parts) < 2:
                        continue
                    # Convierte "DC-97-58" → "DC9758"
                    oui = parts[0].strip().replace('-', '').upper()
                    if len(oui) != 6:
                        continue
                    name = parts[1].strip()
                    if name:
                        db[oui] = name
            if db:
                return db
        except OSError:
            continue
    return _OUI_FALLBACK


# Base de datos OUI cargada una vez al importar el módulo
_OUI_DB: dict = _load_oui_db()


def _lookup_oui(mac: str) -> Optional[str]:
    """
    Devuelve el nombre del fabricante a partir de los primeros 3 bytes del MAC.
    Devuelve None si el OUI no está en la base de datos.
    Solo tiene sentido llamarlo con MACs de tipo 'public' (no aleatorias).
    """
    # Extrae los 3 primeros bytes: "DC:97:58:09:63:7F" → "DC9758"
    oui = mac[:8].replace(':', '').upper()
    return _OUI_DB.get(oui)


# Tabla de campos RadioTap en orden de bit ascendente:
# (bit_en_present, tamaño_bytes, alineación_bytes)
# Alineación medida desde el byte 0 del header RadioTap (= byte 0 del raw recibido).
# Fuente: https://www.radiotap.org/fields/
_RT_FIELDS = (
    (0,  8, 8),   # TSFT          — timestamp µs del receptor (u64)
    (1,  1, 1),   # Flags         — atributos del frame; bit 4 = FCS presente al final
    (2,  1, 1),   # Rate          — tasa de datos en unidades de 500 Kbps
    (3,  4, 2),   # Channel       — 2 bytes frecuencia MHz (u16) + 2 bytes channel flags
    (4,  2, 1),   # FHSS          — hop set (u8) + hop pattern (u8); solo en FHSS
    (5,  1, 1),   # dBm Ant Sig   — RSSI en dBm (int8 signed)   ← el que usamos
    (6,  1, 1),   # dBm Ant Noise — nivel de ruido en dBm (int8 signed)
    (7,  2, 2),   # Lock Quality  — calidad de sincronización del receptor
    (8,  2, 2),   # TX Attenuation
    (9,  2, 2),   # dB TX Attenuation
    (10, 1, 1),   # dBm TX Power
    (11, 1, 1),   # Antenna       — índice de antena (para diversidad)
    (12, 1, 1),   # dB Ant Signal — señal relativa en dB (no calibrada)
    (13, 1, 1),   # dB Ant Noise
    (14, 2, 2),   # RX Flags      — CRC bad, etc.
    (15, 2, 2),   # TX Flags
    (16, 1, 1),   # RTS Retries
    (17, 1, 1),   # Data Retries
)

# Códigos de escape ANSI para colorear la salida en terminal
RED    = '\033[91m'   # rojo    → dentro del aula (RSSI >= -85)
YELLOW = '\033[93m'   # amarillo → cerca          (RSSI >= -95)
WHITE  = '\033[97m'   # blanco  → fuera            (RSSI <  -95)
CYAN   = '\033[96m'   # cian    → cabecera de tabla
GREEN  = '\033[92m'   # verde   → estado hilo vivo
RESET  = '\033[0m'    # resetea atributos
BOLD   = '\033[1m'    # negrita
CLEAR  = '\033[2J\033[H'   # limpia pantalla y mueve cursor al origen

# Nombre de la interfaz en modo monitor
MONITOR_IFACE = 'wlan1'

# ETH_P_ALL (0x0003): recibe todos los frames de la capa de enlace
ETH_P_ALL = 0x0003

# ── Channel hopping ────────────────────────────────────────────
# Canales 2.4 GHz (normativa europea: 1-13)
_CHANNELS_2GHZ: list = list(range(1, 14))

# Canales 5 GHz más comunes en Europa.
# UNII-1 (sin DFS) son los más seguros para hopping porque el hardware
# no necesita esperar el periodo de "channel availability check" de 60s.
# UNII-2 y UNII-2E requieren DFS; el driver puede rechazar el cambio si no
# hay soporte DFS activo, por lo que se incluyen pero se ignoran los errores.
_CHANNELS_5GHZ: list = [
    36, 40, 44, 48,              # UNII-1  (sin DFS, preferidos)
    52, 56, 60, 64,              # UNII-2  (DFS)
    100, 104, 108, 112, 116,     # UNII-2E (DFS)
    132, 136, 140,               # UNII-2E (DFS)
    149, 153, 157, 161, 165,     # UNII-3  (sin DFS en algunos países)
]

# Tiempo de permanencia en cada canal antes de saltar al siguiente (segundos).
# Con 200 ms: un barrido completo de 2.4 GHz dura 13 × 0.2 = 2.6 s.
# Reducirlo mejora la cobertura temporal pero puede perder frames cortos.
HOP_INTERVAL_DEFAULT: float = 0.20


# ──────────────────────────────────────────────────────────────
# MODELO DE DATOS
# ──────────────────────────────────────────────────────────────

@dataclass
class WifiDevice:
    """
    Representa un dispositivo Wi-Fi detectado por su dirección transmisora (addr2).
    Se actualiza en tiempo real cada vez que se recibe un frame del mismo MAC.
    """
    mac:          str            # XX:XX:XX:XX:XX:XX mayúsculas — dirección transmisora (addr2)
    ssid:         Optional[str]  # SSID anunciado (Beacon) o buscado (Probe Request); '' = wildcard
    rssi:         Optional[int]  # potencia de señal recibida en dBm (negativo)
    channel:      Optional[int]  # canal 802.11 (1-13 en 2.4GHz, 36-165 en 5GHz)
    frequency:    Optional[int]  # frecuencia en MHz
    frame_type:   str            # tipo del último frame recibido (BEACON, PROBE_REQ, etc.)
    addr_type:    str            # 'random' si MAC locally-administered, 'public' si OUI global
    is_protected: bool           # True si se detectó RSN IE (WPA2/WPA3) o WPA IE
    manufacturer: Optional[str]  # fabricante según OUI; None si MAC aleatoria o OUI desconocido
    first_seen:   float          = field(default_factory=time.time)
    last_seen:    float          = field(default_factory=time.time)

    @property
    def proximity(self) -> str:
        """
        Clasifica la proximidad del dispositivo en tres zonas según el RSSI.
        Umbrales calibrados para aula estándar con paredes de hormigón.

        Devuelve:
          'dentro'      — RSSI >= -85 dBm: el dispositivo está dentro del aula
          'cerca'       — RSSI >= -95 dBm: está justo fuera o en el pasillo
          'fuera'       — RSSI <  -95 dBm: lejos del perímetro
          'desconocido' — aún no se ha recibido ningún RSSI
        """
        if self.rssi is None:
            return 'desconocido'
        if self.rssi >= -85:
            return 'dentro'
        if self.rssi >= -95:
            return 'cerca'
        return 'fuera'


# ──────────────────────────────────────────────────────────────
# PARSEO RADIOTAP
# ──────────────────────────────────────────────────────────────

def _parse_radiotap(raw: bytes) -> dict:
    """
    Parsea el header RadioTap que el driver antepone a cada frame 802.11 capturado
    en modo monitor.

    Estructura del header RadioTap:
      [0]    revision  = 0 (siempre cero)
      [1]    pad       = 0 (relleno de alineación)
      [2:4]  length    — tamaño total del header en bytes (LE); offset al frame 802.11
      [4:8]  present   — bitmask LE con los campos presentes; bit 31 = sigue otra palabra

    Los campos siguen al último bloque de palabras 'present' y se leen en orden
    creciente de bit. Cada campo se alinea a su alineación natural medida desde
    el byte 0 del header (byte 0 del raw recibido).

    Comportamiento del bit 4 del campo Flags (bit 1 de present):
      Cuando está activo, el driver ha dejado el FCS (4 bytes) al final del frame
      802.11. En ese caso hay que ignorar los últimos 4 bytes del frame al parsear IEs.
      Los drivers mac80211 modernos lo suelen quitar, pero se comprueba por seguridad.

    Devuelve un dict con:
      header_len  — bytes que ocupa el header RadioTap
      rssi        — señal en dBm (int) o None
      frequency   — frecuencia en MHz (int) o None
      channel     — número de canal calculado de la frecuencia (int) o None
      fcs_present — True si el frame 802.11 lleva FCS al final (hay que recortarlo)
    """
    result: dict = {
        'header_len':  0,
        'rssi':        None,
        'frequency':   None,
        'channel':     None,
        'fcs_present': False,
    }

    if len(raw) < 8:
        return result

    # Lee la longitud total del header (bytes [2:4] little-endian)
    header_len = struct.unpack_from('<H', raw, 2)[0]
    result['header_len'] = min(header_len, len(raw))

    # Lee la primera palabra 'present' (siempre en bytes [4:8] little-endian)
    # Si bit 31 está activo, otra palabra present sigue encadenada.
    # Solo usamos la primera (cubre bits 0-28, más que suficiente para RSSI y Channel).
    present = struct.unpack_from('<I', raw, 4)[0]

    # Calcula dónde empiezan los campos: avanza más allá de todas las palabras present
    offset = 4
    while True:
        w = struct.unpack_from('<I', raw, offset)[0]
        offset += 4
        if not (w & (1 << 31)):   # bit 31 = 0 → esta es la última palabra present
            break

    # Recorre los campos en orden de bit (tabla _RT_FIELDS)
    for bit, size, align in _RT_FIELDS:
        if not (present & (1 << bit)):
            continue   # este campo no está en el header

        # Alinea el offset desde el byte 0 del header (= inicio de raw)
        if align > 1 and (offset % align) != 0:
            offset += align - (offset % align)

        # Protección: no leer más allá del header declarado
        if offset + size > result['header_len']:
            break

        if bit == 1:   # Flags: bit 4 indica FCS presente al final del frame
            flags_byte = raw[offset]
            result['fcs_present'] = bool(flags_byte & 0x10)

        elif bit == 3:   # Channel: 2 bytes frecuencia (MHz) + 2 bytes channel flags
            freq = struct.unpack_from('<H', raw, offset)[0]
            result['frequency'] = freq
            # Convierte frecuencia a número de canal según la banda
            if 2412 <= freq <= 2472:
                result['channel'] = (freq - 2407) // 5   # 2412→1, 2417→2 … 2472→13
            elif freq == 2484:
                result['channel'] = 14                    # canal 14 (solo en Japón)
            elif 5180 <= freq <= 5825:
                result['channel'] = (freq - 5000) // 5   # 5180→36, 5200→40 …

        elif bit == 5:   # dBm Antenna Signal: int8 signed = RSSI en dBm
            result['rssi'] = struct.unpack_from('b', raw, offset)[0]

        offset += size

    return result


# ──────────────────────────────────────────────────────────────
# PARSEO CABECERA 802.11 MAC
# ──────────────────────────────────────────────────────────────

def _mac_str(raw6: bytes) -> str:
    """Convierte 6 bytes de dirección MAC a la cadena XX:XX:XX:XX:XX:XX en mayúsculas."""
    return ':'.join(f'{b:02X}' for b in raw6)


def _is_random_mac(raw6: bytes) -> bool:
    """
    Detecta si una dirección MAC es locally-administered (aleatorizada).
    El bit 1 (0x02) del primer octeto a 1 indica dirección local, no asignada por el IEEE.
    Los teléfonos modernos usan MACs aleatorias en Probe Requests para proteger la privacidad.
    """
    return bool(raw6[0] & 0x02)


def _is_unicast_mac(raw6: bytes) -> bool:
    """
    El bit 0 (0x01) del primer octeto a 0 indica dirección unicast.
    Las direcciones broadcast/multicast tienen ese bit a 1 y no representan un dispositivo concreto.
    """
    return not (raw6[0] & 0x01)


def _parse_dot11_header(frame: bytes) -> Optional[dict]:
    """
    Parsea la cabecera MAC 802.11 de un frame de gestión.

    Estructura del Frame Control (2 bytes, little-endian):
      Byte 0:
        bits 0-1 — Protocol Version (siempre 00 en 802.11)
        bits 2-3 — Type:    00=Management, 01=Control, 10=Data, 11=Extension
        bits 4-7 — Subtype: identifica el subtipo dentro del tipo
      Byte 1 (Frame Control Flags):
        bit 0 — To DS         (frame hacia el Distribution System)
        bit 1 — From DS       (frame desde el DS)
        bit 2 — More Fragments
        bit 3 — Retry         (retransmisión)
        bit 4 — Power Management
        bit 5 — More Data
        bit 6 — Protected Frame (cuerpo del frame cifrado con WEP/WPA/MFP)
        bit 7 — Order / HTC present

    Cabecera fija de un Management Frame (24 bytes):
      [0:2]   Frame Control   — tipo, subtipo y flags
      [2:4]   Duration/ID     — µs reservados para el canal durante la transacción
      [4:10]  Addr1           — Destination (receptor del frame)
      [10:16] Addr2           — Source (transmisor del frame) ← identificador del dispositivo
      [16:22] Addr3           — BSSID u otra dirección según el subtipo
      [22:24] Sequence Control — número de fragmento (4 bits) + número de secuencia (12 bits)

    Nota: Addr4 (6 bytes adicionales) solo existe en frames de datos cuando
    ToDS=1 AND FromDS=1 simultáneamente (punto a punto dentro del DS).
    En frames de gestión esto no ocurre, así que siempre son 24 bytes fijos.

    Devuelve None si el frame es demasiado corto o no es un frame de gestión.
    """
    if len(frame) < 24:
        return None

    fc0 = frame[0]   # primer byte del Frame Control
    fc1 = frame[1]   # segundo byte del Frame Control (flags)

    # Extrae type y subtype del primer byte del Frame Control
    fc_type = (fc0 >> 2) & 0x03   # bits 2-3: tipo de frame
    subtype  = (fc0 >> 4) & 0x0F  # bits 4-7: subtipo

    # Solo procesamos frames de gestión
    if fc_type != FRAME_TYPE_MGMT:
        return None

    # Flags del segundo byte del Frame Control
    protected = bool(fc1 & 0x40)   # bit 6: frame protegido (MFP — Management Frame Protection)

    # Extrae las tres direcciones MAC de la cabecera fija
    addr1_raw = frame[4:10]    # dirección destino (receptor)
    addr2_raw = frame[10:16]   # dirección origen  (transmisor) ← clave para identificar
    addr3_raw = frame[16:22]   # BSSID u otra dirección

    # Los IEs empiezan en el byte 24 (cabecera MAC fija) más los campos fijos
    # propios del subtipo (timestamp, capabilities, reason code, etc.).
    # Sin este ajuste, _parse_ies leería basura como si fueran IEs.
    body_offset = 24 + _FIXED_FIELDS_SIZE.get(subtype, 0)

    return {
        'subtype':     subtype,
        'protected':   protected,
        'addr1':       _mac_str(addr1_raw),
        'addr2':       _mac_str(addr2_raw),
        'addr3':       _mac_str(addr3_raw),
        'addr2_raw':   addr2_raw,   # bytes crudos para detectar MAC aleatoria y unicast
        'body_offset': body_offset,
    }


# ──────────────────────────────────────────────────────────────
# PARSEO INFORMATION ELEMENTS (IEs)
# ──────────────────────────────────────────────────────────────

def _parse_ies(body: bytes) -> dict:
    """
    Parsea los Information Elements del cuerpo de un frame de gestión 802.11.

    Los IEs utilizan el formato TLV (Type-Length-Value), idéntico en estructura
    a los AD structures de Bluetooth. Se concatenan directamente uno tras otro.

    Estructura de cada IE:
      [0]        Tag Number  — tipo del elemento
      [1]        Tag Length  — bytes de valor que siguen (sin incluir estos 2 bytes)
      [2:2+len]  Value       — datos del elemento

    IEs procesados:
      Tag 0x00 (IE_SSID)     — nombre de la red en UTF-8
                               length=0 → wildcard (Probe Request sin SSID concreto)
      Tag 0x03 (IE_DS_PARAM) — canal actual del AP (1 byte u8)
      Tag 0x30 (IE_RSN)      — RSN Information Element → indica WPA2 o WPA3
      Tag 0xDD (IE_VENDOR)   — Vendor Specific: si OUI=00:50:F2 + type=0x01 → WPA1

    IEs ignorados intencionadamente:
      Tag 0x01 — Supported Rates: tasas de datos soportadas (no relevante)
      Tag 0x07 — Country: código de país (no relevante)
      Tag 0x2D — HT Capabilities: parámetros 802.11n (no relevante)
      Tag 0x3D — HT Operation (no relevante)
      Resto    — silenciados

    Devuelve:
      ssid     — nombre de red (str), '' si wildcard, None si no hay IE_SSID
      channel  — número de canal (int) o None si no hay IE_DS_PARAM
      is_wpa2  — True si hay RSN IE presente (WPA2 o WPA3)
      is_wpa   — True si hay Vendor Specific WPA IE de Microsoft (WPA1)
    """
    result: dict = {'ssid': None, 'channel': None, 'is_wpa2': False, 'is_wpa': False}
    i = 0

    while i < len(body):
        # Cabecera mínima: 2 bytes (tag + length)
        if i + 2 > len(body):
            break

        tag    = body[i]
        length = body[i + 1]
        i += 2

        # Protección contra IEs con length que excede el buffer restante
        if i + length > len(body):
            break

        value = body[i: i + length]
        i += length

        # ── SSID ──────────────────────────────────────────────
        if tag == IE_SSID:
            if length == 0:
                # Wildcard SSID: el dispositivo busca cualquier red disponible
                # Se distingue de None (IE_SSID no presente) con cadena vacía ''
                result['ssid'] = ''
            else:
                try:
                    result['ssid'] = value.decode('utf-8', errors='replace').strip('\x00')
                except Exception:
                    pass

        # ── DS Parameter Set — canal ───────────────────────────
        elif tag == IE_DS_PARAM and length >= 1:
            # Un solo byte con el número de canal en el que opera el AP
            result['channel'] = value[0]

        # ── RSN — WPA2 / WPA3 ─────────────────────────────────
        elif tag == IE_RSN:
            # Solo necesitamos saber que está presente (indica cifrado moderno)
            result['is_wpa2'] = True

        # ── Vendor Specific — WPA1 (Microsoft OUI) ────────────
        elif tag == IE_VENDOR and length >= 4:
            # Los primeros 3 bytes son el OUI del vendedor, el 4.º el subtipo
            # OUI=00:50:F2 + tipo=0x01 → WPA Information Element (anterior a RSN/WPA2)
            if value[:4] == _MS_OUI_WPA:
                result['is_wpa'] = True

    return result


# ──────────────────────────────────────────────────────────────
# DISPLAY
# ──────────────────────────────────────────────────────────────

def _signal_bar(rssi: Optional[int], width: int = 8) -> str:
    """
    Genera una barra de señal visual usando bloques Unicode.
    Rango de referencia: -100 dBm = completamente vacía, -40 dBm = completamente llena.
    """
    if rssi is None:
        return '░' * width
    normalized = max(0.0, min(1.0, (rssi + 100) / 60.0))
    filled = round(normalized * width)
    return '█' * filled + '░' * (width - filled)


def _proximity_color(proximity: str) -> str:
    """Devuelve el código ANSI correspondiente a la zona de proximidad."""
    return {'dentro': RED, 'cerca': YELLOW, 'fuera': WHITE}.get(proximity, WHITE)


def _render_table(devices: list) -> str:
    """
    Construye la cadena de texto completa de la tabla de dispositivos Wi-Fi.
    Ordenada por RSSI descendente (el más cercano aparece primero).
    """
    lines = []
    lines.append(
        f"{BOLD}{CYAN}{'TIPO':<10} {'MAC':<19} {'RSSI':>5}  {'SEÑAL':<10} "
        f"{'PROX':<12} {'CH':>4}  {'FABRICANTE / SSID'}{RESET}"
    )
    lines.append('─' * 90)

    for dev in sorted(devices, key=lambda d: d.rssi if d.rssi is not None else -999, reverse=True):
        color    = _proximity_color(dev.proximity)
        bar      = _signal_bar(dev.rssi)
        rssi_str = f'{dev.rssi:+4d}' if dev.rssi is not None else '  N/A'
        ch_str   = str(dev.channel) if dev.channel is not None else '?'
        age      = int(time.time() - dev.last_seen)

        # Representación del SSID:
        #   None  → el dispositivo no ha anunciado SSID todavía
        #   ''    → Probe Request wildcard (busca cualquier red)
        #   str   → SSID conocido (truncado a 20 caracteres)
        if dev.ssid is None:
            ssid_display = ''
        elif dev.ssid == '':
            ssid_display = '<wildcard>'
        else:
            ssid_display = f'"{dev.ssid[:20]}"'

        # Fabricante desde OUI (solo en MACs públicas); en MACs aleatorias muestra [R]
        if dev.addr_type == 'random':
            fab = '[R]'
        elif dev.manufacturer:
            fab = dev.manufacturer[:18]
        else:
            fab = '?'

        # Indicadores de cifrado y separador fabricante/SSID
        enc  = ' [WPA]' if dev.is_protected else ''
        info = f'{fab:<18}  {ssid_display}{enc}' if ssid_display else f'{fab}{enc}'

        lines.append(
            f"{color}{dev.frame_type:<10} {dev.mac:<19} {rssi_str}  {bar:<10} "
            f"{dev.proximity:<12} {ch_str:>4}  {info}  [{age}s]{RESET}"
        )

    return '\n'.join(lines)


# ──────────────────────────────────────────────────────────────
# CHANNEL HOPPING
# ──────────────────────────────────────────────────────────────

def _set_channel(iface: str, channel: int) -> bool:
    """
    Cambia el canal de la interfaz Wi-Fi usando el comando 'iw'.

    Por qué subprocess aquí y no en el parseo de paquetes:
      Cambiar el canal es una operación de gestión del driver (nl80211),
      no de parseo de tramas. La única forma estándar de hacerlo sin
      librerías externas es invocar 'iw' o usar netlink directamente;
      esta segunda opción requiere decenas de líneas de código frágil
      y no aporta valor al TFG. 'iw' es la herramienta oficial del kernel.

    Devuelve True si el cambio se realizó con éxito, False en caso contrario.
    Los fallos silenciosos son habituales en canales DFS o no soportados
    por el hardware; el hopper simplemente pasa al siguiente canal.
    """
    try:
        result = subprocess.run(
            ['iw', 'dev', iface, 'set', 'channel', str(channel)],
            capture_output=True,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────
# SCANNER PRINCIPAL
# ──────────────────────────────────────────────────────────────

class WifiScanner:
    """
    Scanner Wi-Fi 802.11 pasivo en modo monitor.
    Captura tramas de gestión sobre wlan1 (Alfa AWUS036ACHM) sin inyectar nada.

    Uso básico:
        scanner = WifiScanner()
        scanner.start()
        # ... leer scanner.devices periódicamente ...
        scanner.stop()
    """

    def __init__(self, iface: str = MONITOR_IFACE,
                 on_device: Optional[Callable[[WifiDevice], None]] = None,
                 hop_interval: float = HOP_INTERVAL_DEFAULT,
                 scan_5ghz: bool = False):
        """
        Inicializa el scanner sin arrancarlo.

        Parámetros:
          iface        — interfaz en modo monitor (por defecto wlan1)
          on_device    — callback llamado cada vez que se detecta un dispositivo nuevo
          hop_interval — segundos de permanencia en cada canal (por defecto 0.20 s)
          scan_5ghz    — si True, incluye los canales 5 GHz en el hopping
        """
        self._iface        = iface
        self.on_device     = on_device
        self._hop_interval = hop_interval
        self._scan_5ghz    = scan_5ghz

        # Caché de dispositivos detectados, indexado por addr2 (MAC transmisora)
        self._seen: dict[str, WifiDevice] = {}
        self._lock = threading.Lock()   # protege _seen contra accesos concurrentes

        # Cola para desacoplar captura (hilo socket) de notificación (hilo dispatch)
        self._event_queue: queue.Queue = queue.Queue()

        # Event de control de ciclo de vida: set=corriendo, clear=parar
        self._running = threading.Event()

        self._cap_thread:  Optional[threading.Thread] = None
        self._disp_thread: Optional[threading.Thread] = None
        self._hop_thread:  Optional[threading.Thread] = None

        # Canal actualmente sintonizado; lo actualiza _hop_loop y lo lee main()
        self.current_channel: Optional[int] = None

    # ── API pública ────────────────────────────────────────────

    def start(self) -> None:
        """
        Arranca el scanner lanzando tres hilos daemon:
          - wifi-cap:      captura y parsea frames del socket AF_PACKET
          - wifi-dispatch: entrega WifiDevice nuevos al callback on_device
          - wifi-hop:      cambia el canal de wlan1 periódicamente
        """
        self._running.set()
        self._cap_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name='wifi-cap'
        )
        self._disp_thread = threading.Thread(
            target=self._dispatch_loop, daemon=True, name='wifi-dispatch'
        )
        self._hop_thread = threading.Thread(
            target=self._hop_loop, daemon=True, name='wifi-hop'
        )
        self._cap_thread.start()
        self._disp_thread.start()
        self._hop_thread.start()

    def stop(self) -> None:
        """Detiene el scanner señalizando los hilos para que salgan en su próxima iteración."""
        self._running.clear()

    @property
    def devices(self) -> list:
        """Devuelve una copia thread-safe de la lista de dispositivos detectados."""
        with self._lock:
            return list(self._seen.values())

    # ── Hilo de captura ────────────────────────────────────────

    def _capture_loop(self) -> None:
        """
        Hilo único de captura. Abre un socket AF_PACKET RAW sobre la interfaz monitor
        y lee frames 802.11 con header RadioTap hasta que stop() lo señalice.

        Por qué AF_PACKET / SOCK_RAW / ETH_P_ALL:
          En modo monitor el driver mac80211 presenta los frames capturados del aire
          como si fueran frames Ethernet en la interfaz wlan1, pero con un header
          RadioTap prepended que contiene metadatos de RF (RSSI, canal, tasa, etc.).
          AF_PACKET + SOCK_RAW + ETH_P_ALL recibe todos estos frames tal cual.

        Requiere CAP_NET_RAW (ejecutar como root).
        La interfaz wlan1 debe estar ya en modo monitor antes de llamar a start().
        """
        try:
            # AF_PACKET: opera a nivel de capa de enlace (por debajo de IP)
            # SOCK_RAW:  recibe el frame completo sin ningún procesado del kernel
            # htons(ETH_P_ALL): recibe todos los frames independientemente del protocolo
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
            )
            # Asocia el socket a la interfaz en modo monitor
            sock.bind((self._iface, 0))
            # Timeout de 1s para que el bucle pueda comprobar _running periódicamente
            sock.settimeout(1.0)
        except OSError as e:
            print(f'[wifi] Error al abrir socket en {self._iface}: {e}', file=sys.stderr)
            return

        try:
            while self._running.is_set():
                try:
                    raw = sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    # Error puntual de I/O: se intenta continuar en lugar de abortar
                    continue
                self._handle_frame(raw)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── Channel hopping ───────────────────────────────────────

    def _hop_loop(self) -> None:
        """
        Hilo de channel hopping. Cicla por todos los canales configurados
        y cambia wlan1 a cada uno mediante 'iw', esperando hop_interval
        segundos antes de pasar al siguiente.

        Secuencia de canales:
          2.4 GHz: 1 → 2 → … → 13 → 1 → … (siempre activo)
          5 GHz:   intercalados con los 2.4 GHz si scan_5ghz=True

        El bucle de dwell usa incrementos de 50 ms en lugar de un único
        time.sleep(hop_interval) para reaccionar rápidamente a stop().

        Por qué el hopper vive en su propio hilo y no en el de captura:
          El recv() del hilo de captura bloquea hasta que llega un frame
          (o hasta el timeout de 1s). Si el hopper viviera ahí, el cambio
          de canal se retrasaría hasta el próximo frame o el timeout, lo
          que rompería la cadencia de hopping en canales silenciosos.
        """
        channels = _CHANNELS_2GHZ[:]
        if self._scan_5ghz:
            channels += _CHANNELS_5GHZ

        for ch in itertools.cycle(channels):
            if not self._running.is_set():
                break

            ok = _set_channel(self._iface, ch)
            if ok:
                self.current_channel = ch

            # Permanece en el canal hop_interval segundos.
            # El sleep se hace en trozos de 50 ms para poder salir limpiamente
            # cuando stop() borra _running antes de que expire el intervalo.
            deadline = time.monotonic() + self._hop_interval
            while self._running.is_set() and time.monotonic() < deadline:
                time.sleep(0.05)

    # ── Procesado de cada frame ────────────────────────────────

    def _handle_frame(self, raw: bytes) -> None:
        """
        Procesa un frame capturado por el socket.

        Flujo:
          1. Parsea el header RadioTap → RSSI, canal, frecuencia
          2. Avanza al frame 802.11 (offset = header_len, menos FCS si procede)
          3. Parsea la cabecera 802.11 → descarta si no es Management frame de interés
          4. Descarta si addr2 no es unicast (evita registrar broadcast/multicast)
          5. Parsea los IEs → SSID, canal, WPA2
          6. Registra o actualiza el dispositivo en el caché
        """
        # Paso 1: RadioTap
        rt = _parse_radiotap(raw)
        header_len = rt['header_len']
        if header_len >= len(raw):
            return

        # El frame 802.11 empieza tras el header RadioTap
        # Si el driver dejó el FCS (4 bytes al final), lo eliminamos antes de parsear
        fcs_trim = 4 if rt['fcs_present'] else 0
        frame_end = len(raw) - fcs_trim
        frame = raw[header_len: frame_end]

        # Paso 2: cabecera 802.11
        dot11 = _parse_dot11_header(frame)
        if dot11 is None:
            return   # no es Management frame o demasiado corto

        subtype = dot11['subtype']
        if subtype not in SUBTYPE_NAMES:
            return   # subtipo no relevante para detección de fraude

        # Paso 3: filtro de addr2 (solo transmisores unicast tienen sentido)
        if not _is_unicast_mac(dot11['addr2_raw']):
            return

        # Paso 4: IEs — se parsean siempre; si el frame está MFP-protegido
        # el parser devuelve simplemente los defaults sin crashear
        body_start = dot11['body_offset']
        ies: dict  = {'ssid': None, 'channel': None, 'is_wpa2': False, 'is_wpa': False}
        if len(frame) > body_start:
            ies = _parse_ies(frame[body_start:])

        # Paso 5: el canal del IE_DS_PARAM es más preciso que el del RadioTap
        # (RadioTap refleja el canal en el que el receptor estaba sintonizado,
        # que puede diferir del canal del AP en redes con banda dual)
        channel = ies.get('channel') or rt.get('channel')

        report = {
            'mac':          dot11['addr2'],
            'mac_raw':      dot11['addr2_raw'],
            'ssid':         ies.get('ssid'),
            'rssi':         rt.get('rssi'),
            'channel':      channel,
            'frequency':    rt.get('frequency'),
            'frame_type':   SUBTYPE_NAMES[subtype],
            'is_protected': dot11['protected'] or ies['is_wpa2'] or ies['is_wpa'],
        }
        self._register_device(report)

    # ── Registro de dispositivos ───────────────────────────────

    def _register_device(self, report: dict) -> None:
        """
        Registra o actualiza un dispositivo Wi-Fi en el caché _seen.

        Clave de indexación: addr2 (MAC transmisora).

        Si la MAC ya existe:
          - Actualiza last_seen, rssi, frame_type
          - Actualiza ssid y channel solo si el nuevo frame los trae (no sobreescribe con None)
          - is_protected es acumulativo: una vez detectado cifrado no se borra

        Si es nueva:
          - Crea el WifiDevice y lo encola para el callback on_device
        """
        mac = report['mac']
        now = time.time()

        with self._lock:
            if mac in self._seen:
                dev            = self._seen[mac]
                dev.last_seen  = now
                dev.frame_type = report['frame_type']

                if report['rssi'] is not None:
                    dev.rssi = report['rssi']
                if report['ssid'] is not None:
                    dev.ssid = report['ssid']
                if report['channel'] is not None:
                    dev.channel = report['channel']
                if report['frequency'] is not None:
                    dev.frequency = report['frequency']
                if report['is_protected']:
                    dev.is_protected = True
            else:
                addr_type = 'random' if _is_random_mac(report['mac_raw']) else 'public'
                # El fabricante solo se puede determinar con MACs públicas (OUI real).
                # En MACs aleatorias los primeros 3 bytes no identifican a nadie.
                manufacturer = _lookup_oui(mac) if addr_type == 'public' else None
                dev = WifiDevice(
                    mac=mac,
                    ssid=report['ssid'],
                    rssi=report['rssi'],
                    channel=report['channel'],
                    frequency=report['frequency'],
                    frame_type=report['frame_type'],
                    addr_type=addr_type,
                    is_protected=report['is_protected'],
                    manufacturer=manufacturer,
                    first_seen=now,
                    last_seen=now,
                )
                self._seen[mac] = dev
                self._event_queue.put(dev)

    # ── Hilo de dispatch ───────────────────────────────────────

    def _dispatch_loop(self) -> None:
        """
        Entrega WifiDevice nuevos al callback on_device desde la cola interna.
        Desacopla la recepción de frames (hilo socket) de la notificación al usuario,
        evitando que un callback lento bloquee la captura de paquetes.
        """
        while self._running.is_set():
            try:
                dev = self._event_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if self.on_device:
                try:
                    self.on_device(dev)
                except Exception:
                    pass


# ──────────────────────────────────────────────────────────────
# PUNTO DE ENTRADA
# ──────────────────────────────────────────────────────────────

def main() -> None:
    """
    Punto de entrada del script. Requiere root para abrir el socket AF_PACKET RAW.
    Muestra una tabla que se refresca cada segundo con los dispositivos activos
    en los últimos 20 segundos, ordenados por RSSI descendente.
    Para con Ctrl+C e imprime el resumen final.
    """
    if os.geteuid() != 0:
        print('Error: se requiere ejecutar como root (sudo).')
        sys.exit(1)

    print(f'Interfaz: {MONITOR_IFACE}  (debe estar en modo monitor)')
    print('Iniciando scanner Wi-Fi 802.11... (Ctrl+C para parar)')
    time.sleep(0.5)

    scanner    = WifiScanner(iface=MONITOR_IFACE)
    start_time = time.time()
    scanner.start()

    try:
        while True:
            ahora   = time.time()
            elapsed = int(ahora - start_time)

            # Solo muestra dispositivos que hayan emitido en los últimos 20 segundos.
            # Los que llevan más de 20s sin aparecer se ocultan pero siguen en el caché.
            devs = [d for d in scanner.devices if (ahora - d.last_seen) <= 20]

            ch_now = scanner.current_channel
            ch_str = f'CH {ch_now}' if ch_now else 'cambiando...'

            print(CLEAR, end='')
            print(f"{BOLD}=== TFG Detector Fraude Académico — Wi-Fi Scanner 802.11 ==={RESET}")
            print(
                f"  Hora: {time.strftime('%H:%M:%S')}  |  Activo: {elapsed}s  |  "
                f"Dispositivos activos: {len(devs)}  |  "
                f"Total detectados: {len(scanner.devices)}  |  Ctrl+C para parar"
            )
            print(f"  Interfaz: {MONITOR_IFACE}  |  Escuchando: {ch_str}  |  "
                  f"[R] = MAC aleatoria  |  [WPA] = red cifrada")
            print()

            if devs:
                print(_render_table(devs))
            else:
                print('  Escuchando frames 802.11 de gestión...')

            time.sleep(1.0)

    except KeyboardInterrupt:
        pass

    finally:
        scanner.stop()
        all_devs = scanner.devices
        print(
            f'\n{BOLD}Escaneo finalizado. '
            f'Total dispositivos detectados: {len(all_devs)}{RESET}'
        )
        for dev in sorted(all_devs, key=lambda d: d.rssi or -999, reverse=True):
            enc  = ' WPA' if dev.is_protected else ''
            rnd  = ' [R]' if dev.addr_type == 'random' else ''
            ssid = f'  SSID={dev.ssid!r}' if dev.ssid is not None else ''
            fab  = f'  {dev.manufacturer}' if dev.manufacturer else ''
            print(
                f'  {dev.frame_type:<10} {dev.mac}  RSSI={dev.rssi}  '
                f'PROX={dev.proximity}  CH={dev.channel}{enc}{rnd}{fab}{ssid}'
            )


if __name__ == '__main__':
    main()
