#!/usr/bin/env python3
"""
wifi_capture.py — Scanner Wi-Fi 802.11 en modo monitor para TFG detección fraude académico.
Raspberry Pi 5, Alfa AWUS036ACHM (MT7612U), Raspberry Pi OS Bookworm ARM64.
Sin dependencias externas. Sockets AF_PACKET RAW únicamente.

La interfaz wlan1 debe estar en modo monitor antes de ejecutar el script.
"""

import itertools
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
# Solo se procesan frames DATA (type=0x02). Gestión y Control se descartan.
FRAME_TYPE_DATA = 0x02   # Data: tráfico de usuario


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

# Nombre de la interfaz en modo monitor
MONITOR_IFACE = 'wlan1'

# ETH_P_ALL (0x0003): recibe todos los frames de la capa de enlace
ETH_P_ALL = 0x0003

# ── Channel hopping ────────────────────────────────────────────
# Canales 2.4 GHz
_CHANNELS_2GHZ: list = list(range(1, 14))

# Tiempo de permanencia en cada canal antes de saltar al siguiente (segundos).
# Con 200 ms: un barrido completo de 2.4 GHz dura 13 × 0.2 = 2.6 s.
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
    channel:      Optional[int]  # canal 802.11 (1-13 en 2.4GHz)
    frequency:    Optional[int]  # frecuencia en MHz
    frame_type:   str            # tipo del último frame recibido (BEACON, PROBE_REQ, etc.)
    manufacturer: Optional[str]  # fabricante según OUI; None si OUI desconocido
    first_seen:   float          = field(default_factory=time.time)
    last_seen:    float          = field(default_factory=time.time)

    @property
    def proximity(self) -> str:
        """
        Clasifica la proximidad del dispositivo en tres zonas según el RSSI.
        Umbrales calibrados para aula estándar con paredes de hormigón.

        Devuelve:
          'cerca'           — RSSI >= -85 dBm: el dispositivo está muy próximo
          'dentro del aula' — RSSI >= -95 dBm: está en el aula o pasillo contiguo
          'fuera'           — RSSI <  -95 dBm: lejos del perímetro
          'desconocido'     — aún no se ha recibido ningún RSSI
        """
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


def _is_unicast_mac(raw6: bytes) -> bool:
    """
    El bit 0 (0x01) del primer octeto a 0 indica dirección unicast.
    Las direcciones broadcast/multicast tienen ese bit a 1 y no representan un dispositivo concreto.
    """
    return not (raw6[0] & 0x01)


def _parse_dot11_header(frame: bytes) -> Optional[dict]:
    """
    Parsea la cabecera MAC 802.11 y devuelve los campos necesarios para
    identificar el transmisor de un frame DATA.

    Estructura del Frame Control (2 bytes):
      Byte 0:
        bits 2-3 — Type:    0x02 = Data
      Byte 1 (flags):
        bit 0 — To DS   (1 = frame hacia el AP)
        bit 1 — From DS (1 = frame desde el AP → se descarta en _process_frame)

    Cabecera fija 802.11 (24 bytes):
      [4:10]  Addr2 — transmisor del frame ← MAC del dispositivo cliente
      [10:16] Addr2 es siempre el transmisor independientemente de ToDS/FromDS

    Devuelve None si el frame es demasiado corto o no es un frame DATA.
    """
    if len(frame) < 24:
        return None

    fc0 = frame[0]
    fc1 = frame[1]

    fc_type = (fc0 >> 2) & 0x03   # bits 2-3: tipo de frame
    from_ds = (fc1 >> 1) & 0x01   # bit 1: frame procedente del AP

    if fc_type != FRAME_TYPE_DATA:
        return None

    addr2_raw = frame[10:16]   # transmisor del frame ← MAC del dispositivo

    return {
        'from_ds':   from_ds,
        'addr2':     _mac_str(addr2_raw),
        'addr2_raw': addr2_raw,
    }




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
                 hop_interval: float = HOP_INTERVAL_DEFAULT):
        """
        Inicializa el scanner sin arrancarlo.

        Parámetros:
          iface        — interfaz en modo monitor (por defecto wlan1)
          on_device    — callback llamado cada vez que se detecta un dispositivo nuevo
          hop_interval — segundos de permanencia en cada canal (por defecto 0.20 s)
        """
        self._iface        = iface
        self.on_device     = on_device
        self._hop_interval = hop_interval

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

        La interfaz wlan1 debe estar ya en modo monitor antes de llamar a start().
        """
        try:
            # AF_PACKET: opera a nivel de capa de enlace (por debajo de IP)
            # SOCK_RAW:  recibe el frame completo
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

        Secuencia de canales: 1 → 2 → … → 13 → 1 → … (ciclo continuo)

        El bucle de dwell usa incrementos de 50 ms en lugar de un único
        time.sleep(hop_interval) para reaccionar rápidamente a stop().
        """
        for ch in itertools.cycle(_CHANNELS_2GHZ):
            if not self._running.is_set():
                break

            ok = _set_channel(self._iface, ch)
            if ok:
                self.current_channel = ch

            # Permanece en el canal hop_interval x segundos.
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
          3. Descarta si no es frame DATA
          4. Descarta si from_ds=1 (AP→cliente: el transmisor sería el AP, no un dispositivo)
          5. Descarta si addr2 no es unicast
          6. Registra o actualiza el dispositivo en el caché
        """
        # Paso 1: RadioTap
        rt = _parse_radiotap(raw)
        header_len = rt['header_len']
        if header_len >= len(raw):
            return

        fcs_trim = 4 if rt['fcs_present'] else 0
        frame = raw[header_len: len(raw) - fcs_trim]

        # Paso 2: cabecera 802.11 — descarta todo lo que no sea DATA
        dot11 = _parse_dot11_header(frame)
        if dot11 is None:
            return

        # Paso 3: descarta tráfico AP→cliente (from_ds=1); solo nos interesa cliente→AP
        if dot11['from_ds'] == 1:
            return

        # Paso 4: solo transmisores unicast
        if not _is_unicast_mac(dot11['addr2_raw']):
            return

        report = {
            'mac':        dot11['addr2'],
            'ssid':       None,
            'rssi':       rt.get('rssi'),
            'channel':    rt.get('channel'),
            'frequency':  rt.get('frequency'),
            'frame_type': 'DATA',
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
            else:
                dev = WifiDevice(
                    mac=mac,
                    ssid=report['ssid'],
                    rssi=report['rssi'],
                    channel=report['channel'],
                    frequency=report['frequency'],
                    frame_type=report['frame_type'],
                    manufacturer=_lookup_oui(mac),
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
