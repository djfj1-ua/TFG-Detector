"""
Bluetooth scanner — BLE y Clásico vía raw HCI socket.
Sin dependencias externas ni subprocess.
"""

import ctypes
import socket
import struct
import threading
import queue
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constantes HCI
# ──────────────────────────────────────────────────────────────────────────────

HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT   = 0x04

# OGF (Opcode Group Field)
OGF_LINK_CTL = 0x01
OGF_LE_CTL   = 0x08

# OCF — Link Control
OCF_INQUIRY = 0x0001

# OCF — LE Controller
OCF_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_LE_SET_SCAN_ENABLE     = 0x000C

# Códigos de evento HCI
HCI_EVENT_COMMAND_COMPLETE  = 0x0E
HCI_EV_INQUIRY_COMPLETE     = 0x01
HCI_EV_INQUIRY_RESULT_RSSI  = 0x22
HCI_EV_EXTENDED_INQUIRY     = 0x2F
HCI_EVENT_LE_META           = 0x3E

# Subevento LE Meta
LE_META_ADVERTISING_REPORT = 0x02

# Tipos de dirección BLE
BLE_ADDR_PUBLIC = 0x00
BLE_ADDR_RANDOM = 0x01

# Tipos de evento advertising BLE
ADV_IND         = 0x00  # connectable undirected
ADV_DIRECT_IND  = 0x01  # connectable directed
ADV_SCAN_IND    = 0x02  # scannable undirected
ADV_NONCONN_IND = 0x03  # non-connectable undirected
SCAN_RSP        = 0x04  # scan response

ADV_TYPE_NAMES = {
    ADV_IND:         "ADV_IND",
    ADV_DIRECT_IND:  "ADV_DIRECT_IND",
    ADV_SCAN_IND:    "ADV_SCAN_IND",
    ADV_NONCONN_IND: "ADV_NONCONN_IND",
    SCAN_RSP:        "SCAN_RSP",
}

# LAP para Inquiry General (GIAC)
INQUIRY_LAP = b'\x33\x8B\x9E'  # 0x9E8B33 en little-endian

# AD types (usados tanto en BLE advertising como en EIR clásico)
AD_FLAGS               = 0x01
AD_UUID16_INCOMPLETE   = 0x02
AD_UUID16_COMPLETE     = 0x03
AD_UUID32_INCOMPLETE   = 0x04
AD_UUID32_COMPLETE     = 0x05
AD_UUID128_INCOMPLETE  = 0x06
AD_UUID128_COMPLETE    = 0x07
AD_SHORT_NAME          = 0x08
AD_COMPLETE_NAME       = 0x09
AD_TX_POWER            = 0x0A
AD_MANUFACTURER_DATA   = 0xFF


# ──────────────────────────────────────────────────────────────────────────────
# Dataclass para dispositivos Bluetooth detectados
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class BTDevice:
    mac: str
    name: Optional[str]
    rssi: Optional[int]           # dBm
    bt_type: str                  # 'BLE' | 'CLASSIC'
    addr_type: str                # 'public' | 'random' | 'unknown'
    adv_type: Optional[str]       # ADV_IND, SCAN_RSP, etc. (sólo BLE)
    manufacturer_id: Optional[int]
    uuids: list = field(default_factory=list)
    raw_adv_data: bytes = field(default_factory=bytes)
    first_seen: float = field(default_factory=time.time)
    last_seen: float  = field(default_factory=time.time)

    def __post_init__(self):
        self.mac = self.mac.upper()

    @property
    def is_random_address(self) -> bool:
        return self.addr_type == 'random'

    @property
    def proximity(self) -> str:
        """Clasifica la proximidad según RSSI."""
        if self.rssi is None:
            return 'unknown'
        if self.rssi >= -85:
            return 'dentro'
        if self.rssi >= -95:
            return 'cerca'
        return 'fuera'


# ──────────────────────────────────────────────────────────────────────────────
# Parseo de AD structures (BLE advertising y EIR clásico comparten formato)
# ──────────────────────────────────────────────────────────────────────────────

def parse_ad_structures(data: bytes) -> dict:
    """
    Parsea los AD structures (TLV: length, type, value).
    Usado tanto en payloads BLE como en EIR de Inquiry Clásico.
    """
    result = {
        'name': None,
        'flags': None,
        'tx_power': None,
        'uuids': [],
        'manufacturer_id': None,
        'manufacturer_data': None,
    }

    offset = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        offset += 1
        if offset + length > len(data):
            break

        ad_type  = data[offset]
        ad_value = data[offset + 1: offset + length]
        offset  += length

        if ad_type in (AD_SHORT_NAME, AD_COMPLETE_NAME):
            try:
                result['name'] = ad_value.decode('utf-8', errors='replace').rstrip('\x00')
            except Exception:
                pass

        elif ad_type == AD_FLAGS:
            if ad_value:
                result['flags'] = ad_value[0]

        elif ad_type == AD_TX_POWER:
            if ad_value:
                result['tx_power'] = struct.unpack_from('b', ad_value, 0)[0]

        elif ad_type in (AD_UUID16_COMPLETE, AD_UUID16_INCOMPLETE):
            for i in range(0, len(ad_value) - 1, 2):
                uuid = struct.unpack_from('<H', ad_value, i)[0]
                result['uuids'].append(f"{uuid:04X}")

        elif ad_type in (AD_UUID32_COMPLETE, AD_UUID32_INCOMPLETE):
            for i in range(0, len(ad_value) - 3, 4):
                uuid = struct.unpack_from('<I', ad_value, i)[0]
                result['uuids'].append(f"{uuid:08X}")

        elif ad_type == AD_MANUFACTURER_DATA:
            if len(ad_value) >= 2:
                result['manufacturer_id'] = struct.unpack_from('<H', ad_value, 0)[0]
                result['manufacturer_data'] = ad_value[2:].hex()

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Construcción de paquetes HCI
# ──────────────────────────────────────────────────────────────────────────────

class _KernelHciFilter(ctypes.Structure):
    """
    Refleja el struct hci_filter del kernel Linux.
    En kernels 64-bit (ARM64) 'unsigned long' ocupa 8 bytes → struct de 32 bytes.
    ctypes calcula el tamaño correcto según la plataforma.
    """
    _fields_ = [
        ('type_mask',  ctypes.c_ulong),
        ('event_mask', ctypes.c_ulong * 2),
        ('opcode',     ctypes.c_uint16),
    ]


def build_hci_filter(ptype: int, *events: int) -> bytes:
    """
    Construye el struct hci_filter con el tamaño nativo del kernel.
    Acepta múltiples eventos para filtrar simultáneamente.

    ptype  : tipo de paquete (HCI_EVENT_PKT = 0x04)
    events : uno o más códigos de evento HCI a dejar pasar

    Nota de implementación (Pi 5, kernel 6.12 ARM64):
    El kernel de esta plataforma usa el bit (event & 31) dentro de
    event_mask[0] para todos los eventos, independientemente del código.
    Verificado empíricamente: 0x3E→bit30, 0x22→bit2, 0x2F→bit15, 0x01→bit1.
    """
    f = _KernelHciFilter()
    f.type_mask = 1 << ptype
    for event in events:
        f.event_mask[0] |= 1 << (event & 31)
    f.opcode = 0
    return bytes(f)


def build_hci_cmd(ogf: int, ocf: int, params: bytes = b'') -> bytes:
    """Construye un HCI Command Packet."""
    opcode = (ogf << 10) | ocf
    return struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params


def cmd_inquiry() -> bytes:
    """
    Construye el comando HCI_Inquiry.
      LAP           = 0x9E8B33 (GIAC — General Inquiry Access Code)
      Inquiry_Length = 4  →  4 × 1.28 s ≈ 5.12 s por ciclo
      Num_Responses  = 0  →  sin límite
    """
    params = INQUIRY_LAP + struct.pack('<BB', 4, 0)
    return build_hci_cmd(OGF_LINK_CTL, OCF_INQUIRY, params)


def mac_from_bytes(addr: bytes) -> str:
    """Convierte 6 bytes little-endian a string XX:XX:XX:XX:XX:XX."""
    return ':'.join(f'{b:02X}' for b in reversed(addr))


# ──────────────────────────────────────────────────────────────────────────────
# Parseo de eventos HCI
# ──────────────────────────────────────────────────────────────────────────────

def parse_le_advertising_report(payload: bytes) -> list[dict]:
    """
    Parsea el payload de un LE Advertising Report (subevent 0x02).
    'payload' empieza DESPUÉS del subevent code.

    Estructura por report:
      Event_Type  (1B) | Address_Type (1B) | Address (6B) | Data_Length (1B) | Data
    RSSI (1B signed) al final de cada report.
    """
    if not payload:
        return []

    num_reports = payload[0]
    offset = 1
    reports = []

    for _ in range(num_reports):
        if offset + 9 > len(payload):
            break

        event_type  = payload[offset]
        addr_type   = payload[offset + 1]
        addr_bytes  = payload[offset + 2: offset + 8]
        data_length = payload[offset + 8]
        offset += 9

        if offset + data_length > len(payload):
            break

        adv_data = payload[offset: offset + data_length]
        offset  += data_length

        ad = parse_ad_structures(adv_data)

        reports.append({
            'event_type':      event_type,
            'event_type_name': ADV_TYPE_NAMES.get(event_type, f'UNK_{event_type:#04x}'),
            'addr_type':       'public' if addr_type == BLE_ADDR_PUBLIC else 'random',
            'mac':             mac_from_bytes(addr_bytes),
            'name':            ad['name'],
            'uuids':           ad['uuids'],
            'manufacturer_id': ad['manufacturer_id'],
            'raw_adv_data':    adv_data,
            'rssi':            None,
        })

    # RSSI: 1 byte signed al final de cada report (en orden)
    for r in reports:
        if offset < len(payload):
            r['rssi'] = struct.unpack_from('b', payload, offset)[0]
            offset += 1

    return reports


def parse_inquiry_result_rssi(params: bytes) -> list[dict]:
    """
    Parsea el evento HCI_EV_INQUIRY_RESULT_RSSI (0x22).

    Estructura:
      Num_Responses (1B)
      Por cada respuesta (15 bytes):
        BD_ADDR                    (6B, little-endian)
        Page_Scan_Repetition_Mode  (1B)
        Reserved                   (2B)
        Class_of_Device            (3B)
        Clock_Offset               (2B)
        RSSI                       (1B, signed)
    """
    if not params:
        return []

    num = params[0]
    results = []
    ENTRY = 15  # bytes por respuesta

    for i in range(num):
        offset = 1 + i * ENTRY
        if offset + ENTRY > len(params):
            break

        addr_bytes = params[offset:     offset + 6]
        # page_scan_mode = params[offset + 6]
        # reserved       = params[offset + 7 : offset + 9]
        cod        = params[offset + 9:  offset + 12]
        clock_off  = struct.unpack_from('<H', params, offset + 12)[0]
        rssi       = struct.unpack_from('b',  params, offset + 14)[0]

        results.append({
            'mac':          mac_from_bytes(addr_bytes),
            'cod':          cod.hex(),
            'clock_offset': clock_off,
            'rssi':         rssi,
            'name':         None,
            'uuids':        [],
            'manufacturer_id': None,
        })

    return results


def parse_extended_inquiry_result(params: bytes) -> list[dict]:
    """
    Parsea el evento HCI_EV_EXTENDED_INQUIRY (0x2F).
    Siempre contiene exactamente 1 respuesta.

    Estructura (255 bytes totales):
      Num_Responses              (1B)  — siempre 1
      BD_ADDR                    (6B)
      Page_Scan_Repetition_Mode  (1B)
      Reserved                   (1B)
      Class_of_Device            (3B)
      Clock_Offset               (2B)
      RSSI                       (1B, signed)
      Extended_Inquiry_Response  (240B, formato TLV igual que AD structures BLE)
    """
    if len(params) < 255:
        return []

    # params[0] = num_responses (siempre 1, no lo usamos)
    addr_bytes = params[1:7]
    # page_scan  = params[7]
    # reserved   = params[8]
    cod        = params[9:12]
    clock_off  = struct.unpack_from('<H', params, 12)[0]
    rssi       = struct.unpack_from('b',  params, 14)[0]
    eir        = params[15:255]   # 240 bytes de EIR data

    ad = parse_ad_structures(eir)

    return [{
        'mac':             mac_from_bytes(addr_bytes),
        'cod':             cod.hex(),
        'clock_offset':    clock_off,
        'rssi':            rssi,
        'name':            ad['name'],
        'uuids':           ad['uuids'],
        'manufacturer_id': ad['manufacturer_id'],
    }]


# ──────────────────────────────────────────────────────────────────────────────
# Scanner principal
# ──────────────────────────────────────────────────────────────────────────────

class BluetoothScanner:
    """
    Escanea BLE y Bluetooth Clásico en un único hilo vía raw HCI socket.

    BLE    → LE Advertising Reports continuos.
    Clásico → HCI Inquiry cíclico con RSSI y EIR; se relanza automáticamente
              al recibir el evento Inquiry_Complete.

    Uso:
        scanner = BluetoothScanner(dev_id=0, on_device=callback)
        scanner.start()
        time.sleep(60)
        scanner.stop()
    """

    def __init__(
        self,
        dev_id: int = 0,
        on_device: Optional[Callable[[BTDevice], None]] = None,
        ble_scan_type: int = 0x00,   # 0=pasivo, 1=activo
    ):
        self.dev_id       = dev_id
        self.on_device    = on_device
        self.ble_scan_type = ble_scan_type

        self._running = threading.Event()

        # Caché de dispositivos vistos: mac → BTDevice
        self._seen: dict[str, BTDevice] = {}
        self._seen_lock = threading.Lock()

        # Cola interna para desacoplar detección de callback
        self._event_queue: queue.Queue[BTDevice] = queue.Queue()

    # ── Ciclo de vida ────────────────────────────────────────────────────────

    def start(self):
        if self._running.is_set():
            return
        self._running.set()

        threading.Thread(target=self._ble_loop,     name="bt-scanner",    daemon=True).start()
        threading.Thread(target=self._dispatch_loop, name="bt-dispatcher", daemon=True).start()
        log.info("BluetoothScanner iniciado (hci%d)", self.dev_id)

    def stop(self):
        self._running.clear()
        self._send_disable_scan()
        log.info("BluetoothScanner detenido")

    @property
    def devices(self) -> list[BTDevice]:
        with self._seen_lock:
            return list(self._seen.values())

    # ── Socket HCI ───────────────────────────────────────────────────────────

    def _open_hci_socket(self) -> socket.socket:
        """
        Abre un raw HCI socket filtrado para recibir:
          - LE Meta Events (BLE advertising)
          - Inquiry Result with RSSI (BT clásico)
          - Extended Inquiry Result (BT clásico con EIR)
          - Inquiry Complete (para relanzar el inquiry)
        """
        sock = socket.socket(
            socket.AF_BLUETOOTH,
            socket.SOCK_RAW,
            socket.BTPROTO_HCI,
        )
        sock.bind((self.dev_id,))
        sock.settimeout(2.0)

        hci_filter = build_hci_filter(
            HCI_EVENT_PKT,
            HCI_EVENT_LE_META,
            HCI_EV_INQUIRY_RESULT_RSSI,
            HCI_EV_EXTENDED_INQUIRY,
            HCI_EV_INQUIRY_COMPLETE,
        )
        sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, hci_filter)
        return sock

    def _send_hci_cmd(self, sock: socket.socket, ogf: int, ocf: int, params: bytes = b''):
        cmd = build_hci_cmd(ogf, ocf, params)
        sock.send(cmd)

    def _send_disable_scan(self):
        """Desactiva el BLE scan al parar — lanza su propio socket temporal."""
        try:
            sock = self._open_hci_socket()
            self._send_hci_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                               struct.pack("<BB", 0x00, 0x00))
            sock.close()
        except Exception:
            pass

    # ── Loop principal ───────────────────────────────────────────────────────

    # Segundos entre Inquiries clásicos.
    # El Inquiry dura INQUIRY_DURATION × 1.28 s ≈ 5 s (duration=4).
    # Con INQUIRY_INTERVAL=10 el ciclo es: 5s Inquiry + 5s BLE limpio.
    # Máxima espera para detectar un Classic BT que entra en discoverable: ~10s.
    INQUIRY_INTERVAL = 10

    def _ble_loop(self):
        """
        BLE activo de forma continua; Inquiry clásico periódico cada
        INQUIRY_INTERVAL segundos. Un dispositivo que aparezca en cualquier
        momento es detectado en segundos por BLE, sin tener que esperar
        al final de un ciclo de Inquiry.
        """
        while self._running.is_set():
            try:
                sock = self._open_hci_socket()
                self._enable_ble_scan(sock)

                # Primer Inquiry tras 5 s de BLE limpio
                next_inquiry = time.time() + 5

                while self._running.is_set():
                    try:
                        raw = sock.recv(1024)
                    except socket.timeout:
                        if time.time() >= next_inquiry:
                            sock.send(cmd_inquiry())
                        continue
                    except OSError:
                        break

                    inquiry_done = self._handle_hci_event(raw, sock)
                    if inquiry_done:
                        # Inquiry completado → programar el siguiente
                        next_inquiry = time.time() + self.INQUIRY_INTERVAL

                sock.close()
            except PermissionError:
                log.error("Scanner necesita privilegios root (PermissionError)")
                self._running.clear()
                break
            except Exception as e:
                log.warning("Scanner error: %s — reintentando en 3s", e)
                time.sleep(3)

    def _enable_ble_scan(self, sock: socket.socket):
        """Configura y activa el escaneo LE con ventana amplia."""
        params = struct.pack(
            "<BHHBB",
            self.ble_scan_type,  # LE_Scan_Type: 0=pasivo, 1=activo
            0x0200,              # LE_Scan_Interval: 320 ms  (0x0200 × 0.625 ms)
            0x0200,              # LE_Scan_Window:   320 ms  (duty cycle 100%)
            0x00,                # Own_Address_Type: public
            0x00,                # Scanning_Filter_Policy: aceptar todo
        )
        self._send_hci_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, params)
        time.sleep(0.05)
        self._send_hci_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                           struct.pack("<BB", 0x01, 0x00))  # enable, sin filtrar duplicados


    # ── Parseo de eventos ────────────────────────────────────────────────────

    def _handle_hci_event(self, raw: bytes, sock: socket.socket) -> bool:
        """
        Despacha un paquete HCI recibido según su event code.
        Devuelve True cuando el Inquiry completa (señal para que _receive_loop salga).

        Formato del paquete:
          [0]  HCI packet type (0x04 = event)
          [1]  Event code
          [2]  Parameter total length
          [3:] Parameters
        """
        if len(raw) < 3 or raw[0] != HCI_EVENT_PKT:
            return False

        event_code = raw[1]
        params     = raw[3:]

        if event_code == HCI_EVENT_LE_META:
            if len(raw) >= 4 and raw[3] == LE_META_ADVERTISING_REPORT:
                for r in parse_le_advertising_report(raw[4:]):
                    self._register_ble_device(r)

        elif event_code == HCI_EV_INQUIRY_RESULT_RSSI:
            for r in parse_inquiry_result_rssi(params):
                self._register_classic_device(r)

        elif event_code == HCI_EV_EXTENDED_INQUIRY:
            for r in parse_extended_inquiry_result(params):
                self._register_classic_device(r)

        elif event_code == HCI_EV_INQUIRY_COMPLETE:
            return True   # señaliza fin del Inquiry → _ble_loop gestionará la pausa

        return False

    # ── Registro de dispositivos ─────────────────────────────────────────────

    def _register_ble_device(self, report: dict):
        mac = report['mac']
        now = time.time()

        with self._seen_lock:
            if mac in self._seen:
                dev = self._seen[mac]
                dev.last_seen = now
                dev.rssi      = report['rssi']
                if report['name'] and not dev.name:
                    dev.name = report['name']
            else:
                dev = BTDevice(
                    mac=mac,
                    name=report['name'],
                    rssi=report['rssi'],
                    bt_type='BLE',
                    addr_type=report['addr_type'],
                    adv_type=report['event_type_name'],
                    manufacturer_id=report['manufacturer_id'],
                    uuids=report['uuids'],
                    raw_adv_data=report['raw_adv_data'],
                    first_seen=now,
                    last_seen=now,
                )
                self._seen[mac] = dev

        self._event_queue.put(dev)

    def _register_classic_device(self, report: dict):
        mac = report['mac']
        now = time.time()

        with self._seen_lock:
            if mac in self._seen:
                dev = self._seen[mac]
                dev.last_seen = now
                dev.rssi      = report['rssi']
                if report.get('name') and not dev.name:
                    dev.name = report['name']
            else:
                dev = BTDevice(
                    mac=mac,
                    name=report.get('name'),
                    rssi=report['rssi'],
                    bt_type='CLASSIC',
                    addr_type='public',
                    adv_type=None,
                    manufacturer_id=report.get('manufacturer_id'),
                    uuids=report.get('uuids', []),
                    first_seen=now,
                    last_seen=now,
                )
                self._seen[mac] = dev

        self._event_queue.put(dev)

    # ── Dispatcher de callbacks ──────────────────────────────────────────────

    def _dispatch_loop(self):
        """Entrega los BTDevice al callback on_device desde un hilo dedicado."""
        while self._running.is_set() or not self._event_queue.empty():
            try:
                dev = self._event_queue.get(timeout=1)
                if self.on_device:
                    try:
                        self.on_device(dev)
                    except Exception as e:
                        log.error("Error en on_device callback: %s", e)
            except queue.Empty:
                continue


# ──────────────────────────────────────────────────────────────────────────────
# Tabla viva en terminal
# ──────────────────────────────────────────────────────────────────────────────

_RST  = '\033[0m'
_BOLD = '\033[1m'
_RED  = '\033[91m'
_YEL  = '\033[93m'
_WHT  = '\033[97m'
_GRY  = '\033[90m'
_CYA  = '\033[96m'
_CLR  = '\033[2J\033[H'

_PROX_COLOR = {'dentro': _RED, 'cerca': _YEL, 'fuera': _WHT, 'unknown': _GRY}


def _rssi_bar(rssi: int | None, width: int = 8) -> str:
    if rssi is None:
        return '·' * width
    pct = max(0.0, min(1.0, (rssi + 100) / 60))
    n = round(pct * width)
    return '█' * n + '░' * (width - n)


def _render(devices: list[BTDevice], elapsed: int, total: int) -> str:
    devs = sorted(devices, key=lambda d: d.rssi or -120, reverse=True)
    hdr  = f"{'TIPO':<8} {'MAC':<17}  {'RSSI':>8}  {'SEÑAL':<8}  {'PROX':<8}  {'DIR':<3}  NOMBRE"
    sep  = '─' * 78
    out  = [
        f"{_CYA}{_BOLD}  Detector BT  │  {elapsed:>3}/{total}s  │  {len(devs)} dispositivo(s){_RST}",
        f"{_CYA}{sep}{_RST}",
        f"{_BOLD}{hdr}{_RST}",
        f"{_GRY}{sep}{_RST}",
    ]
    for d in devs:
        c   = _PROX_COLOR.get(d.proximity, _GRY)
        rs  = f"{d.rssi:+4d} dBm" if d.rssi is not None else "   ? dBm"
        nom = (d.name or '(sin nombre)')[:38]
        adr = 'rnd' if d.is_random_address else 'pub'
        out.append(
            f"{c}{d.bt_type:<8}{_RST}"
            f" {d.mac:<17}"
            f"  {rs}"
            f"  {_rssi_bar(d.rssi):<8}"
            f"  {c}{d.proximity:<8}{_RST}"
            f"  {adr}"
            f"  {nom}"
        )
    if not devs:
        out.append(f"  {_GRY}Esperando dispositivos…{_RST}")
    out.append(f"{_GRY}{sep}{_RST}")
    return '\n'.join(out)


if __name__ == '__main__':
    import sys

    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

    duration  = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    scan_type = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    scanner = BluetoothScanner(dev_id=0, ble_scan_type=scan_type)
    scanner.start()

    start = time.time()
    try:
        while True:
            elapsed = int(time.time() - start)
            if elapsed >= duration:
                break
            print(_CLR + _render(scanner.devices, elapsed, duration), flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        scanner.stop()

    print(_CLR + _render(scanner.devices, duration, duration))
    print(f"\n{_BOLD}Escaneo completado.{_RST}  Total únicos: {len(scanner.devices)}")
