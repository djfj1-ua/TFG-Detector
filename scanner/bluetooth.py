#!/usr/bin/env python3
"""
bluetoothPrueba.py — Scanner Bluetooth (BLE + Clásico) para TFG detección fraude académico.
Raspberry Pi 5, BCM43455, Raspberry Pi OS Bookworm ARM64.
Sin dependencias externas de Bluetooth. Sockets HCI RAW únicamente.
DEBUG VERSION — escribe log detallado en /tmp/bt_debug.log
"""

import ctypes
import queue
import socket
import struct
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional


# ──────────────────────────────────────────────────────────────
# DEBUG
# ──────────────────────────────────────────────────────────────

_LOG_PATH = '/tmp/bt_debug.log'   # ruta del fichero de log en disco
_log_lock = threading.Lock()      # mutex para que varios hilos no escriban a la vez
_t0       = time.time()           # marca de tiempo del arranque, usada para timestamps relativos


def _dbg(msg: str) -> None:
    """
    Escribe una línea de debug en /tmp/bt_debug.log con timestamp relativo al arranque.
    Usa un Lock para que sea segura desde múltiples hilos simultáneamente.
    """
    # Calcula el tiempo transcurrido desde el arranque del programa
    ts   = f'{time.time() - _t0:+9.3f}s'
    line = f'[{ts}] {msg}\n'

    # Adquiere el mutex antes de escribir para evitar mezcla de líneas entre hilos
    with _log_lock:
        with open(_LOG_PATH, 'a') as f:
            f.write(line)


# Al importar el módulo, borra el log anterior y escribe la cabecera con fecha/hora
with open(_LOG_PATH, 'w') as _f:
    _f.write(f'=== bt_debug.log — {time.strftime("%Y-%m-%d %H:%M:%S")} ===\n')


# ──────────────────────────────────────────────────────────────
# CONSTANTES HCI
# ──────────────────────────────────────────────────────────────

# Tipos de paquete HCI
HCI_COMMAND_PKT = 0x01   # paquete de comando (host → controlador)
HCI_EVENT_PKT   = 0x04   # paquete de evento  (controlador → host)

# Códigos de evento HCI que nos interesan
HCI_EV_INQUIRY_COMPLETE    = 0x01   # fin del período de Inquiry clásico
HCI_EV_INQUIRY_RESULT_RSSI = 0x22   # respuesta de Inquiry con RSSI (sin nombre)
HCI_EV_EXTENDED_INQUIRY    = 0x2F   # respuesta de Inquiry extendida (con nombre EIR)
HCI_EV_LE_META             = 0x3E   # evento contenedor de todos los subeventos BLE
HCI_LE_EV_ADV_REPORT       = 0x02   # subevent dentro de LE_META: advertising report

# OGF (Opcode Group Field): agrupan comandos por categoría
OGF_LE_CTL   = 0x08   # grupo de comandos LE Controller
OGF_LINK_CTL = 0x01   # grupo de comandos Link Control (Inquiry clásico)

# OCF (Opcode Command Field): identifican el comando concreto dentro del OGF
OCF_LE_SET_SCAN_PARAM  = 0x000B   # configurar parámetros del BLE scan
OCF_LE_SET_SCAN_ENABLE = 0x000C   # activar o desactivar el BLE scan
OCF_INQUIRY            = 0x0001   # lanzar un Inquiry Bluetooth clásico

# Mapa de tipos de advertising BLE para mostrar en pantalla
ADV_TYPES = {
    0: 'ADV_IND',      # connectable undirected — el más común
    1: 'ADV_DIRECT',   # connectable directed
    2: 'ADV_SCAN',     # scannable undirected
    3: 'ADV_NONCONN',  # non-connectable undirected
    4: 'SCAN_RSP',     # respuesta a un scan request activo
}

# Códigos de tipo de las estructuras AD/EIR (formato TLV compartido por BLE y Clásico)
# AD_FLAGS = 0x01  # ← NO UTILIZADO: definido en el estándar pero no se procesa en
#                  #   _parse_ad_structures; se ignoran los flags de capacidad BLE.
AD_NAME_SHORT    = 0x08   # nombre abreviado del dispositivo
AD_NAME_COMPLETE = 0x09   # nombre completo del dispositivo
AD_TX_POWER      = 0x0A   # potencia de transmisión en dBm
AD_UUID16_INC    = 0x02   # lista incompleta de UUIDs de 16 bits
AD_UUID16_COMP   = 0x03   # lista completa de UUIDs de 16 bits
AD_UUID128_INC   = 0x06   # lista incompleta de UUIDs de 128 bits
AD_UUID128_COMP  = 0x07   # lista completa de UUIDs de 128 bits
AD_MANUFACTURER  = 0xFF   # datos específicos del fabricante (company ID + payload)

# ──────────────────────────────────────────────────────────────
# HCI FILTER — ARM64 Bookworm (ctypes nativo)
# ──────────────────────────────────────────────────────────────

class _KernelHciFilter(ctypes.Structure):
    """
    Refleja el struct hci_filter del kernel Linux tal como existe en ARM64.
    En ARM64 'unsigned long' ocupa 8 bytes, por lo que el struct mide 32 bytes.
    ctypes calcula el tamaño correcto de forma automática según la plataforma.

    Campos:
      type_mask  — bitmask de tipos de paquete HCI a dejar pasar
      event_mask — bitmask de códigos de evento HCI a dejar pasar (2 × 8 bytes)
      opcode     — filtro opcional por opcode de comando (0 = sin filtro)
    """
    _fields_ = [
        ('type_mask',  ctypes.c_ulong),       # 8 bytes en ARM64
        ('event_mask', ctypes.c_ulong * 2),   # 16 bytes: dos palabras de 8 bytes
        ('opcode',     ctypes.c_uint16),      # 2 bytes
    ]


def _build_hci_filter(*event_codes: int) -> bytes:
    """
    Construye el binario del struct hci_filter para aplicarlo al socket HCI RAW.
    Activa los bits correspondientes a cada evento que queremos recibir.

    IMPORTANTE — comportamiento verificado empíricamente en BCM43455 / kernel 6.x ARM64:
    El kernel usa 'bit = event_code & 31' dentro de event_mask[0] para TODOS los
    eventos, incluidos los de código >= 32. NO distribuye entre event_mask[0] y [1].
    Intentar usar event_mask[1] para códigos altos (ej. 0x3E) rompe la recepción BLE.
    """
    f = _KernelHciFilter()

    # Activa el bit del tipo HCI_EVENT_PKT (0x04) para recibir eventos del controlador
    f.type_mask = 1 << HCI_EVENT_PKT

    # Para cada código de evento, calcula el bit y lo activa en event_mask[0]
    for ev in event_codes:
        bit = ev & 31   # regla del kernel ARM64: siempre módulo 32, siempre word 0
        f.event_mask[0] |= 1 << bit
        _dbg(f'FILTER  ev=0x{ev:02X}  bit={bit}  siempre en word 0')

    # Vuelca los valores finales al log para verificación
    _dbg(
        f'FILTER  type_mask=0x{f.type_mask:08X}  '
        f'event_mask[0]=0x{f.event_mask[0]:016X}  '
        f'event_mask[1]=0x{f.event_mask[1]:016X}  '
        f'sizeof={ctypes.sizeof(f)}'
    )

    # Serializa la estructura a bytes para pasarla a setsockopt
    return bytes(f)


# ──────────────────────────────────────────────────────────────
# MODELO DE DATOS
# ──────────────────────────────────────────────────────────────

@dataclass
class BTDevice:
    """
    Representa un dispositivo Bluetooth detectado (BLE o Clásico).
    Se actualiza en tiempo real cada vez que se recibe un nuevo paquete del mismo MAC.
    """
    mac:             str            # dirección MAC en formato XX:XX:XX:XX:XX:XX mayúsculas
    name:            Optional[str]  # nombre del dispositivo (None si no se ha anunciado)
    rssi:            Optional[int]  # potencia de señal recibida en dBm (negativo)
    bt_type:         str            # 'BLE' o 'CLASSIC'
    addr_type:       str            # 'public' (fija) o 'random' (rotativa, habitual en BLE)
    adv_type:        Optional[str]  = None   # tipo de advertising BLE (ADV_IND, SCAN_RSP…)
    manufacturer_id: Optional[int]  = None   # company ID del fabricante (ej. 0x004C = Apple)
    uuids:           list           = field(default_factory=list)    # servicios anunciados
    first_seen:      float          = field(default_factory=time.time)  # primer avistamiento
    last_seen:       float          = field(default_factory=time.time)  # último avistamiento

    @property
    def proximity(self) -> str:
        """
        Clasifica la proximidad del dispositivo en tres zonas según el RSSI.
        Los umbrales están calibrados para un aula estándar con paredes de hormigón.

        Devuelve:
          'cerca'         — RSSI >= -85 dBm: el dispositivo está muy próximo
          'dentro del aula' — RSSI >= -95 dBm: está en el aula o pasillo contiguo
          'fuera'         — RSSI <  -95 dBm: está lejos, fuera del perímetro
          'desconocido'   — si aún no se ha recibido ningún RSSI
        """
        if self.rssi is None:
            return 'desconocido'
        if self.rssi >= -85:
            return 'cerca'
        if self.rssi >= -95:
            return 'dentro del aula'
        return 'fuera'


# ──────────────────────────────────────────────────────────────
# PARSEO AD / EIR
# ──────────────────────────────────────────────────────────────

def _parse_ad_structures(data: bytes) -> dict:
    """
    Parsea las estructuras AD (Advertising Data) o EIR (Extended Inquiry Response).
    Ambos formatos son idénticos: bloques TLV (Type-Length-Value) concatenados.

    Estructura de cada bloque:
      [0]        length  — número de bytes que siguen (incluye el byte de tipo)
      [1]        type    — código que identifica qué contiene el bloque
      [2:length] value   — datos del bloque (length-1 bytes)

    Devuelve un dict con las claves: 'name', 'tx_power', 'uuids', 'manufacturer_id'.
    Los campos que no aparezcan en los datos quedan como None o lista vacía.
    """
    result: dict = {
        'uuids':           [],
        'manufacturer_id': None,
        'name':            None,
        'tx_power':        None,
    }

    i = 0
    while i < len(data):
        # Lee el byte de longitud del bloque actual
        length = data[i]

        # Un length=0 indica relleno hasta el final del buffer, se salta
        if length == 0:
            i += 1
            continue

        # Si el bloque se saldría del buffer, los datos están corruptos; se aborta
        if i + length >= len(data):
            break

        # Extrae tipo y valor del bloque
        ad_type  = data[i + 1]
        ad_value = data[i + 2: i + 1 + length]

        # Avanza el puntero al siguiente bloque
        i += 1 + length

        # ── Nombre del dispositivo ──────────────────────────────
        if ad_type in (AD_NAME_SHORT, AD_NAME_COMPLETE):
            # Decodifica UTF-8 tolerante a errores y elimina nulos de relleno
            try:
                result['name'] = ad_value.decode('utf-8', errors='replace').strip('\x00')
            except Exception:
                pass

        # ── Potencia de transmisión ─────────────────────────────
        elif ad_type == AD_TX_POWER and len(ad_value) >= 1:
            # TX Power es un int8 signed (puede ser negativo)
            result['tx_power'] = struct.unpack('b', ad_value[:1])[0]

        # ── UUIDs de 16 bits ────────────────────────────────────
        elif ad_type in (AD_UUID16_INC, AD_UUID16_COMP):
            # Cada UUID ocupa 2 bytes little-endian; se formatean como hex de 4 dígitos
            for j in range(0, len(ad_value) - 1, 2):
                uuid16 = struct.unpack_from('<H', ad_value, j)[0]
                result['uuids'].append(f'{uuid16:04X}')

        # ── UUIDs de 128 bits ───────────────────────────────────
        elif ad_type in (AD_UUID128_INC, AD_UUID128_COMP):
            # Cada UUID ocupa 16 bytes little-endian; se invierte para obtener big-endian estándar
            for j in range(0, len(ad_value) - 15, 16):
                raw = ad_value[j:j + 16][::-1]
                result['uuids'].append(raw.hex())

        # ── Datos del fabricante ────────────────────────────────
        elif ad_type == AD_MANUFACTURER and len(ad_value) >= 2:
            # Los primeros 2 bytes son el company ID (ej. 0x004C = Apple, 0x0006 = Microsoft)
            result['manufacturer_id'] = struct.unpack_from('<H', ad_value)[0]

        # Nota: AD_FLAGS (0x01) se ignora intencionadamente.
        # Contiene flags de capacidad BLE (LE General Discoverable, BR/EDR Not Supported…)
        # que no son relevantes para los objetivos del TFG.

    return result


def _mac_from_bytes_le(raw: bytes) -> str:
    """
    Convierte una dirección MAC de 6 bytes en formato little-endian (como llega en HCI)
    a la cadena legible estándar XX:XX:XX:XX:XX:XX en mayúsculas.

    Ejemplo: b'\\x87\\xbe\\x07\\x3b\\x16\\x40' → '40:16:3B:07:BE:87'
    """
    # reversed() invierte el orden de bytes (de little-endian a big-endian)
    return ':'.join(f'{b:02X}' for b in reversed(raw))


# ──────────────────────────────────────────────────────────────
# COMANDOS HCI
# ──────────────────────────────────────────────────────────────

def _hci_cmd(ogf: int, ocf: int, params: bytes = b'') -> bytes:
    """
    Construye un paquete HCI Command listo para enviar por el socket RAW.

    Formato del paquete HCI Command:
      [0]    packet_type  = 0x01 (HCI_COMMAND_PKT)
      [1:3]  opcode       = (OGF << 10) | OCF, en little-endian
      [3]    param_length = longitud de los parámetros
      [4:]   params       = parámetros del comando
    """
    # El opcode combina OGF (6 bits superiores) y OCF (10 bits inferiores)
    opcode = (ogf << 10) | ocf

    # Empaqueta cabecera + parámetros en un único bytes
    return struct.pack('<BHB', HCI_COMMAND_PKT, opcode, len(params)) + params


def cmd_le_set_scan_params(scan_type: int = 0x01) -> bytes:
    """
    Construye el comando HCI_LE_Set_Scan_Parameters (OGF=0x08, OCF=0x000B).
    Configura cómo se realizará el BLE scan antes de activarlo.

    Parámetros fijados:
      scan_type     = 0x01 (activo): el adaptador envía SCAN_REQ para obtener SCAN_RSP
                    = 0x00 (pasivo): solo escucha, no envía nada (menos detectable)
      interval      = 0x0200 = 512 × 0.625ms = 320ms
      window        = 0x0200 = 320ms  (igual al intervalo → duty cycle 100%)
      own_addr_type = 0x00 (dirección pública del adaptador)
      filter_policy = 0x00 (aceptar todos los dispositivos, sin lista blanca)
    """
    # Empaqueta los 7 bytes de parámetros del comando
    params = struct.pack('<BHHBB', scan_type, 0x0200, 0x0200, 0x00, 0x00)
    return _hci_cmd(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAM, params)


def cmd_le_set_scan_enable(enable: int, filter_dup: int = 0x00) -> bytes:
    """
    Construye el comando HCI_LE_Set_Scan_Enable (OGF=0x08, OCF=0x000C).
    Activa o desactiva el BLE scan previamente configurado.

    Parámetros:
      enable     = 0x01 activa el scan, 0x00 lo desactiva
      filter_dup = 0x00 reporta todos los paquetes (incluidos duplicados del mismo MAC)
                 = 0x01 filtra duplicados (solo reporta la primera vez que ve cada MAC)
                   Se usa 0x00 para actualizar el RSSI continuamente.
    """
    return _hci_cmd(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, bytes([enable, filter_dup]))


def cmd_inquiry(duration: int = 8) -> bytes:
    """
    Construye el comando HCI_Inquiry (OGF=0x01, OCF=0x0001).
    Inicia el proceso de descubrimiento de dispositivos Bluetooth Clásico (BR/EDR).

    Parámetros:
      LAP           = 0x9E8B33 (GIAC — General Inquiry Access Code)
                      Código estándar para discovery general de todos los dispositivos.
                      Se transmite en little-endian: b'\\x33\\x8B\\x9E'
      duration      = unidades de 1.28s → duration=8 equivale a ~10.24 segundos
      num_responses = 0 → sin límite de respuestas
    """
    # LAP en little-endian + duration y num_responses como bytes sin signo
    params = b'\x33\x8B\x9E' + struct.pack('<BB', duration, 0)
    return _hci_cmd(OGF_LINK_CTL, OCF_INQUIRY, params)


# ──────────────────────────────────────────────────────────────
# SCANNER PRINCIPAL
# ──────────────────────────────────────────────────────────────

class BluetoothScanner:
    """
    Scanner Bluetooth que detecta dispositivos BLE y Clásico simultáneamente
    usando un único socket HCI RAW y un único hilo de captura.

    Uso básico:
        scanner = BluetoothScanner()
        scanner.start()
        # ... leer scanner.devices periódicamente ...
        scanner.stop()
    """

    def __init__(self, scan_type: int = 1, on_device: Optional[Callable[[BTDevice], None]] = None):
        """
        Inicializa el scanner sin arrancarlo todavía.

        Parámetros:
          scan_type  — tipo de BLE scan: 1=activo (envía SCAN_REQ), 0=pasivo
          on_device  — callback opcional llamado cada vez que se detecta un dispositivo nuevo
        """
        self._scan_type  = scan_type    # 0=pasivo, 1=activo
        self.on_device   = on_device    # callback externo para nuevos dispositivos

        # Diccionario de dispositivos detectados, indexado por MAC
        self._seen: dict[str, BTDevice] = {}
        self._lock = threading.Lock()   # protege _seen contra accesos concurrentes

        # Cola para desacoplar la detección (hilo HCI) del callback (hilo dispatch)
        self._event_queue: queue.Queue = queue.Queue()

        # Evento de control de ciclo de vida: set=corriendo, clear=parar
        self._running = threading.Event()

        # Referencias a los hilos para poder inspeccionarlos si hace falta
        self._ble_thread:  Optional[threading.Thread] = None
        self._disp_thread: Optional[threading.Thread] = None

        # Referencia al timer del Inquiry para poder cancelarlo en stop()
        self._inquiry_timer: Optional[threading.Timer] = None

        # ── Contadores de debug ────────────────────────────────
        self.dbg_recv_total   = 0       # total de paquetes HCI recibidos
        self.dbg_ble_reports  = 0       # LE Advertising Reports procesados
        self.dbg_inq_results  = 0       # respuestas de Inquiry procesadas
        self.dbg_inq_complete = 0       # eventos INQUIRY_COMPLETE recibidos (esperado: 0)
        self.dbg_unknown_ev   = 0       # eventos no reconocidos que pasaron el filtro
        self.dbg_oserror      = 0       # errores OSError en el recv loop
        self.dbg_loop_alive   = False   # True mientras _ble_loop está ejecutándose
        self.dbg_last_ev_code = 0       # código del último evento HCI recibido
        self.dbg_last_ev_ts   = 0.0     # timestamp del último evento recibido
        self._dbg_lock        = threading.Lock()   # protege los contadores de debug

    def _inc(self, attr: str, delta: int = 1) -> None:
        """
        Incrementa un contador de debug de forma thread-safe.
        Usa setattr/getattr para poder referirse al contador por nombre de cadena.
        """
        with self._dbg_lock:
            setattr(self, attr, getattr(self, attr) + delta)

    # ── API pública ────────────────────────────────────────────

    def start(self) -> None:
        """
        Arranca el scanner lanzando los dos hilos daemon:
          - ble-loop:  captura y parsea eventos HCI del socket RAW
          - dispatch:  entrega BTDevice nuevos al callback on_device
        Los hilos son daemon para que mueran solos si el proceso principal termina.
        """
        _dbg('SCANNER start()')

        # Activa el Event de control; los bucles while de los hilos lo comprueban
        self._running.set()

        # Crea y arranca el hilo de captura HCI
        self._ble_thread = threading.Thread(
            target=self._ble_loop, daemon=True, name='ble-loop'
        )
        # Crea y arranca el hilo de entrega de callbacks
        self._disp_thread = threading.Thread(
            target=self._dispatch_loop, daemon=True, name='dispatch'
        )

        self._ble_thread.start()
        self._disp_thread.start()

    def stop(self) -> None:
        """
        Detiene el scanner de forma ordenada:
          1. Limpia el Event → los bucles while de los hilos salen en su próxima iteración
          2. Cancela el timer del Inquiry si estaba pendiente de disparar
        El socket y los hilos se limpian solos al salir de sus bucles.
        """
        _dbg('SCANNER stop()')

        # Señaliza a todos los hilos que deben terminar
        self._running.clear()

        # Cancela el timer para evitar que relance el Inquiry después de stop()
        if self._inquiry_timer is not None:
            self._inquiry_timer.cancel()

    @property
    def devices(self) -> list:
        """
        Devuelve una copia de la lista de dispositivos detectados hasta el momento.
        Usa el Lock para garantizar consistencia aunque _ble_loop esté actualizando _seen.
        """
        with self._lock:
            return list(self._seen.values())

    # ── Hilo único de captura ──────────────────────────────────

    def _ble_loop(self) -> None:
        """
        Hilo principal de captura. Es el único que lee del socket HCI RAW.
        Abre el socket, configura el filtro, activa el BLE scan, lanza el primer
        Inquiry y luego entra en un bucle recv() indefinido hasta que stop() se llame.

        En caso de excepción no recuperable, loguea el traceback completo y termina.
        El bloque finally garantiza que el socket se cierra siempre.
        """
        _dbg('BLE_LOOP start')
        self.dbg_loop_alive = True
        try:
            # Abre un socket HCI RAW en la familia AF_BLUETOOTH
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)

            # Lo asocia a hci0 (el adaptador BCM43455 de la Raspberry Pi 5)
            sock.bind((0,))
            _dbg('BLE_LOOP socket creado y ligado a hci0')

            # Construye el filtro HCI para recibir solo los eventos que nos interesan
            # NOTA: HCI_EV_INQUIRY_COMPLETE se incluye en el filtro por completitud,
            # pero en la práctica NUNCA llega al socket compartido con BLE en el BCM43455.
            # El ciclo del Inquiry se gestiona mediante un timer temporal en _launch_inquiry.
            filt = _build_hci_filter(
                HCI_EV_LE_META,              # advertising BLE
                HCI_EV_INQUIRY_RESULT_RSSI,  # respuesta Inquiry con RSSI (sin nombre)
                HCI_EV_EXTENDED_INQUIRY,     # respuesta Inquiry extendida (con nombre)
                HCI_EV_INQUIRY_COMPLETE,     # fin del Inquiry (no llega, pero se filtra)
            )
            sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, filt)
            _dbg('BLE_LOOP filtro HCI aplicado')

            # Activa el BLE scan (una sola vez; nunca se desactiva durante el scan normal)
            self._enable_ble_scan(sock)
            _dbg('BLE_LOOP BLE scan activado')

            # Lanza el primer Inquiry clásico e inicia su timer temporal
            self._launch_inquiry(sock)
            _dbg('BLE_LOOP primer Inquiry lanzado')

            # Configura el timeout del recv para que el bucle pueda comprobar _running
            # aunque no lleguen eventos (evita bloquearse indefinidamente)
            sock.settimeout(1.0)

            # ── Bucle principal de recepción ───────────────────
            while self._running.is_set():
                try:
                    # Bloquea hasta recibir un paquete HCI o hasta el timeout de 1s
                    raw = sock.recv(4096)

                    # Actualiza los contadores y el timestamp del último evento
                    self._inc('dbg_recv_total')
                    with self._dbg_lock:
                        self.dbg_last_ev_code = raw[1] if len(raw) > 1 else 0
                        self.dbg_last_ev_ts   = time.time()

                    # Despacha el paquete al manejador de eventos
                    self._handle_hci_event(raw, sock)

                except socket.timeout:
                    # El timeout de 1s expiró sin datos: vuelve a comprobar _running
                    continue

                except OSError as e:
                    # Error de sistema en el recv (p.ej. EBADF si el socket se cerró)
                    # Se loguea pero NO se hace break; se intenta continuar
                    self._inc('dbg_oserror')
                    _dbg(f'BLE_LOOP OSError en recv: {e!r}')
                    _dbg(traceback.format_exc())
                    continue

                except Exception as e:
                    # Cualquier otra excepción inesperada: se loguea y se continúa
                    _dbg(f'BLE_LOOP excepción inesperada: {e!r}')
                    _dbg(traceback.format_exc())
                    continue

            _dbg('BLE_LOOP while salió (_running cleared)')

        except Exception as e:
            # Error fatal durante la apertura o configuración del socket
            _dbg(f'BLE_LOOP CRASH FATAL: {e!r}')
            _dbg(traceback.format_exc())

        finally:
            # Se ejecuta siempre, tanto en salida normal como por excepción
            self.dbg_loop_alive = False
            _dbg('BLE_LOOP terminado')

            # Intenta desactivar el BLE scan antes de cerrar
            try:
                sock.send(cmd_le_set_scan_enable(0))
            except Exception:
                pass

            # Cierra el socket para liberar el recurso del kernel
            try:
                sock.close()
            except Exception:
                pass

    # ── Gestión BLE scan ───────────────────────────────────────

    def _enable_ble_scan(self, sock: socket.socket) -> None:
        """
        Envía al adaptador los dos comandos necesarios para activar el BLE scan:
          1. HCI_LE_Set_Scan_Parameters — configura tipo, intervalo y ventana
          2. HCI_LE_Set_Scan_Enable     — activa el scan con los parámetros anteriores
        El sleep de 50ms entre ambos da tiempo al firmware a procesar el primero.
        """
        # Envía los parámetros (scan_type viene del constructor: 1=activo)
        sock.send(cmd_le_set_scan_params(self._scan_type))

        # Pausa breve para que el firmware procese los parámetros antes del enable
        time.sleep(0.05)

        # Activa el scan; filter_dup=0 para recibir todos los paquetes (RSSI actualizado)
        sock.send(cmd_le_set_scan_enable(1, filter_dup=0))
        _dbg('_enable_ble_scan enviado')

    def _disable_ble_scan(self, sock: socket.socket) -> None:
        """
        Desactiva el BLE scan enviando HCI_LE_Set_Scan_Enable con enable=0.
        Se usa exclusivamente en _on_inquiry_done para hacer el reset del firmware
        BCM43455, que entra en estado silencioso al terminar el Inquiry.
        El sleep de 100ms da tiempo al firmware a procesar el disable.
        """
        try:
            sock.send(cmd_le_set_scan_enable(0))
        except OSError as e:
            # Si el socket ya estuviera cerrado, se loguea y se continúa
            _dbg(f'_disable_ble_scan OSError: {e!r}')

        # Pausa para que el firmware complete el apagado del scan antes del re-enable
        time.sleep(0.1)
        _dbg('_disable_ble_scan enviado')

    # ── Gestión Inquiry ────────────────────────────────────────

    def _launch_inquiry(self, sock: socket.socket) -> None:
        """
        Envía el comando HCI_Inquiry al adaptador e inicia el timer temporal
        que detectará cuándo ha terminado.

        Por qué un timer y no el evento HCI_EV_INQUIRY_COMPLETE:
        En el BCM43455 con socket compartido BLE+Clásico, el evento INQUIRY_COMPLETE
        nunca llega al proceso. En su lugar se usa un timer basado en la duración
        conocida del Inquiry: 8 × 1.28s + 0.5s de margen = 10.74s.
        """
        # Si ya se ha pedido parar, no lanza nada
        if not self._running.is_set():
            return

        try:
            # Envía el comando Inquiry con duración 8 (≈ 10.24 segundos)
            sock.send(cmd_inquiry(duration=8))
            _dbg('_launch_inquiry Inquiry enviado')
        except OSError as e:
            # Si el socket falla al enviar, no tiene sentido iniciar el timer
            _dbg(f'_launch_inquiry OSError: {e!r}')
            return

        # Inicia el timer que disparará _on_inquiry_done cuando el Inquiry deba haber terminado
        self._inquiry_timer = threading.Timer(10.74, self._on_inquiry_done, args=[sock])
        self._inquiry_timer.daemon = True
        self._inquiry_timer.start()
        _dbg('_launch_inquiry timer 10.74s iniciado')

    def _on_inquiry_done(self, sock: socket.socket) -> None:
        """
        Callback del timer: se ejecuta ~10.74s después de lanzar el Inquiry.

        Realiza el ciclo de recuperación del firmware BCM43455:
          1. Desactiva el BLE scan  → el firmware sale del estado silencioso
          2. Reactiva el BLE scan   → el adaptador vuelve a emitir advertising reports
          3. Espera 5s de BLE puro  → timer para lanzar el siguiente Inquiry

        Por qué es necesario el reset BLE:
        Al terminar el Inquiry, el BCM43455 deja de emitir
        CUALQUIER evento HCI (incluidos los BLE advertising reports) hasta que se
        realice este ciclo disable+enable. Sin él, el scanner queda mudo indefinidamente.
        """
        _dbg('_on_inquiry_done disparado')

        # Si se ha pedido parar entre que se lanzó el timer y ahora, no hace nada
        if not self._running.is_set():
            _dbg('_on_inquiry_done abortado (_running cleared)')
            return

        # Paso 1: desactiva el BLE scan para "despertar" el firmware del estado silencioso
        self._disable_ble_scan(sock)

        # Paso 2: reactiva el BLE scan → el adaptador vuelve a emitir eventos normalmente
        self._enable_ble_scan(sock)
        _dbg('_on_inquiry_done BLE reset completado — esperando 5s para próximo Inquiry')

        # Paso 3: espera 5s de BLE puro antes de lanzar el siguiente Inquiry
        # Esto da tiempo a recibir advertising reports sin la interferencia del Inquiry
        self._inquiry_timer = threading.Timer(5.0, self._launch_inquiry, args=[sock])
        self._inquiry_timer.daemon = True
        self._inquiry_timer.start()

    # ── Dispatch de eventos HCI ────────────────────────────────

    def _handle_hci_event(self, raw: bytes, sock: socket.socket) -> None:
        """
        Punto de entrada de todos los paquetes HCI recibidos del socket.
        Valida la cabecera, identifica el tipo de evento y delega al parser específico.
        """
        # Descarta paquetes demasiado cortos para tener cabecera HCI válida
        if len(raw) < 3:
            _dbg(f'EVENT paquete demasiado corto: {raw.hex()}')
            return

        # El primer byte debe ser siempre HCI_EVENT_PKT (0x04)
        if raw[0] != HCI_EVENT_PKT:
            _dbg(f'EVENT tipo inesperado: 0x{raw[0]:02X}  raw={raw[:8].hex()}')
            return

        # Extrae el código de evento y la longitud declarada de parámetros
        ev_code = raw[1]
        plen    = raw[2]
        _dbg(f'EVENT  code=0x{ev_code:02X}  plen={plen}  raw={raw[:min(len(raw), 12)].hex()}')

        # ── BLE Advertising Report (0x3E) ──────────────────────
        if ev_code == HCI_EV_LE_META:
            # Los eventos LE Meta llevan un subevent en el cuarto byte
            subevent = raw[3] if len(raw) >= 4 else 0xFF
            _dbg(f'  LE_META  subevent=0x{subevent:02X}')
            if subevent == HCI_LE_EV_ADV_REPORT:
                self._inc('dbg_ble_reports')
                # El payload del advertising report empieza en raw[4] (después del subevent)
                self._parse_ble_adv_report(raw[4:])

        # ── Inquiry Result con RSSI (0x22) ─────────────────────
        elif ev_code == HCI_EV_INQUIRY_RESULT_RSSI:
            num = raw[3] if len(raw) > 3 else 0
            _dbg(f'  INQUIRY_RESULT_RSSI  num_responses={num}')
            self._inc('dbg_inq_results')
            # Los parámetros empiezan en raw[3] (después de type+code+plen)
            self._parse_inquiry_rssi(raw[3:])

        # ── Extended Inquiry Result (0x2F) ─────────────────────
        elif ev_code == HCI_EV_EXTENDED_INQUIRY:
            _dbg(f'  EXTENDED_INQUIRY_RESULT')
            self._inc('dbg_inq_results')
            self._parse_extended_inquiry(raw[3:])

        # ── Inquiry Complete (0x01) ─────────────────────────────
        elif ev_code == HCI_EV_INQUIRY_COMPLETE:
            # Solo se registra en el log y en el contador.
            # Este evento NO llega al socket compartido BLE+Clásico en el BCM43455,
            # por lo que nunca actúa como trigger. El ciclo se gestiona en _launch_inquiry.
            status = raw[3] if len(raw) > 3 else 0xFF
            _dbg(f'  INQUIRY_COMPLETE  status=0x{status:02X}  (inesperado en socket compartido)')
            self._inc('dbg_inq_complete')

        # ── Evento desconocido ──────────────────────────────────
        else:
            # Un evento que pasó el filtro HCI pero no está en ninguna rama conocida
            _dbg(f'  EVENTO NO FILTRADO  code=0x{ev_code:02X} (llegó igualmente al socket)')
            self._inc('dbg_unknown_ev')

    # ── Parseo BLE Advertising Report ─────────────────────────

    def _parse_ble_adv_report(self, payload: bytes) -> None:
        """
        Parsea el payload de un LE Advertising Report (subevent 0x02 del evento 0x3E).
        Un solo paquete puede contener varios reports consecutivos del mismo barrido.

        Estructura del payload (empieza después del subevent byte):
          [0]          num_reports — cuántos reports vienen en este paquete
          Por cada report:
            [0]        event_type  — tipo de advertising (ADV_IND, SCAN_RSP…)
            [1]        addr_type   — 0=público, 1=aleatorio
            [2:8]      MAC         — dirección en little-endian (6 bytes)
            [8]        data_length — longitud de los AD structures que siguen
            [9:9+N]    AD data     — N bytes de estructuras TLV
            [9+N]      RSSI        — int8 signed (último byte del report)
        """
        if not payload:
            return

        # Número de reports incluidos en este paquete
        num_reports = payload[0]
        _dbg(f'    ADV_REPORT  num={num_reports}')

        offset = 1   # puntero al inicio del primer report
        for i in range(num_reports):
            # Comprueba que quedan al menos 9 bytes para leer la cabecera del report
            if offset + 9 > len(payload):
                _dbg(f'    ADV_REPORT[{i}] truncado en offset={offset}')
                break

            # Lee los campos fijos de la cabecera del report
            event_type = payload[offset]
            addr_type  = payload[offset + 1]
            mac_raw    = payload[offset + 2: offset + 8]
            data_len   = payload[offset + 8]
            offset    += 9   # avanza más allá de la cabecera

            # Comprueba que quedan suficientes bytes para los AD structures
            if offset + data_len > len(payload):
                _dbg(f'    ADV_REPORT[{i}] data truncada data_len={data_len}')
                break

            # Extrae los AD structures y avanza el puntero
            ad_data = payload[offset: offset + data_len]
            offset += data_len

            # El RSSI es el byte inmediatamente después de los AD structures (int8 signed)
            rssi: Optional[int] = None
            if offset < len(payload):
                rssi = struct.unpack('b', bytes([payload[offset]]))[0]
                offset += 1

            # Convierte los bytes de MAC a string legible
            mac    = _mac_from_bytes_le(mac_raw)
            # Parsea los AD structures para extraer nombre, UUIDs, etc.
            parsed = _parse_ad_structures(ad_data)

            _dbg(
                f'    ADV_REPORT[{i}]  mac={mac}  rssi={rssi}  '
                f'type={ADV_TYPES.get(event_type, "??")}  name={parsed.get("name")!r}'
            )

            # Construye el dict de report y lo registra en el caché de dispositivos
            report = {
                'mac':             mac,
                'rssi':            rssi,
                'bt_type':         'BLE',
                'addr_type':       'random' if addr_type else 'public',
                'adv_type':        ADV_TYPES.get(event_type),
                'name':            parsed.get('name'),
                'manufacturer_id': parsed.get('manufacturer_id'),
                'uuids':           parsed.get('uuids', []),
            }
            self._register_ble_device(report)

    # ── Parseo Inquiry Result with RSSI (0x22) ─────────────────

    def _parse_inquiry_rssi(self, payload: bytes) -> None:
        """
        Parsea el evento HCI_EV_INQUIRY_RESULT_RSSI (0x22).
        Contiene respuestas de dispositivos Clásicos que NO han enviado EIR,
        por lo que solo tenemos MAC y RSSI (el nombre llega después con Extended Inquiry).

        Estructura del payload:
          [0]         num_responses — número de dispositivos en esta respuesta
          Por cada dispositivo (15 bytes fijos):
            [0:6]     BD_ADDR       — MAC en little-endian
            [6]       Page_Scan_Repetition_Mode
            [7:9]     Reserved      — 2 bytes sin uso
            [9:12]    Class_of_Device
            [12:14]   Clock_Offset
            [14]      RSSI          — int8 signed
        """
        if not payload:
            return

        num = payload[0]   # número de respuestas en el paquete
        for i in range(num):
            # Calcula el offset de inicio de esta respuesta (15 bytes cada una)
            base = 1 + i * 15

            # Comprueba que los 15 bytes están dentro del payload
            if base + 15 > len(payload):
                break

            # Extrae MAC (6 bytes LE) y RSSI (byte 14, int8 signed)
            mac_raw = payload[base: base + 6]
            rssi    = struct.unpack('b', bytes([payload[base + 14]]))[0]
            mac     = _mac_from_bytes_le(mac_raw)
            _dbg(f'    INQUIRY_RSSI[{i}]  mac={mac}  rssi={rssi}')

            # El nombre llegará más tarde en un Extended Inquiry Result; por ahora es None
            report = {
                'mac':             mac,
                'rssi':            rssi,
                'bt_type':         'CLASSIC',
                'addr_type':       'public',
                'name':            None,
                'manufacturer_id': None,
                'uuids':           [],
            }
            self._register_classic_device(report)

    # ── Parseo Extended Inquiry Result (0x2F) ──────────────────

    def _parse_extended_inquiry(self, payload: bytes) -> None:
        """
        Parsea el evento HCI_EV_EXTENDED_INQUIRY (0x2F).
        Siempre contiene exactamente 1 dispositivo. Incluye nombre y UUIDs en el EIR.

        Estructura del payload (255 bytes totales):
          [0]        num_responses — siempre 1
          [1:7]      BD_ADDR       — MAC en little-endian
          [7]        Page_Scan_Repetition_Mode
          [8]        Reserved
          [9:12]     Class_of_Device
          [12:14]    Clock_Offset
          [14]       RSSI          — int8 signed
          [15:255]   EIR data      — 240 bytes de estructuras TLV (mismo formato que AD)
        """
        # Necesitamos al menos 15 bytes para llegar al RSSI
        if len(payload) < 15:
            return

        # payload[0] = num_responses (siempre 1, no se usa explícitamente)
        mac_raw  = payload[1:7]    # MAC del dispositivo
        rssi     = struct.unpack('b', bytes([payload[14]]))[0]   # RSSI signed

        # Los datos EIR ocupan desde el byte 15 hasta el 255 (máx 240 bytes útiles)
        eir_data = payload[15:255] if len(payload) >= 255 else payload[15:]

        mac    = _mac_from_bytes_le(mac_raw)
        parsed = _parse_ad_structures(eir_data)   # parsea nombre, UUIDs, etc.
        _dbg(f'    EXTENDED_INQ  mac={mac}  rssi={rssi}  name={parsed.get("name")!r}')

        report = {
            'mac':             mac,
            'rssi':            rssi,
            'bt_type':         'CLASSIC',
            'addr_type':       'public',
            'name':            parsed.get('name'),
            'manufacturer_id': parsed.get('manufacturer_id'),
            'uuids':           parsed.get('uuids', []),
        }
        self._register_classic_device(report)

    # ── Registro de dispositivos ───────────────────────────────

    def _register_ble_device(self, report: dict) -> None:
        """
        Registra o actualiza un dispositivo BLE en el caché _seen.

        Si la MAC ya existe: actualiza last_seen, rssi, name (si mejoró) y
        acumula UUIDs y manufacturer_id nuevos.
        Si es nueva: crea el BTDevice y lo encola en _event_queue para el callback.

        Usa _lock para proteger el acceso concurrente a _seen desde múltiples hilos.
        """
        mac = report['mac']
        now = time.time()

        with self._lock:
            if mac in self._seen:
                # Dispositivo ya conocido: actualiza solo los campos que pueden cambiar
                dev           = self._seen[mac]
                dev.last_seen = now

                # Actualiza el RSSI solo si el nuevo valor no es None
                dev.rssi = report['rssi'] if report['rssi'] is not None else dev.rssi

                # Actualiza el nombre si el nuevo paquete lo incluye (SCAN_RSP suele traerlo)
                if report.get('name'):
                    dev.name = report['name']

                # Acumula UUIDs nuevos que no estuvieran ya en la lista
                for u in report.get('uuids', []):
                    if u not in dev.uuids:
                        dev.uuids.append(u)

                # Actualiza el manufacturer_id si este paquete lo trae
                if report.get('manufacturer_id') is not None:
                    dev.manufacturer_id = report['manufacturer_id']

            else:
                # Dispositivo nuevo: crea el dataclass y lo añade al caché
                dev = BTDevice(
                    mac=mac,
                    name=report.get('name'),
                    rssi=report['rssi'],
                    bt_type='BLE',
                    addr_type=report.get('addr_type', 'public'),
                    adv_type=report.get('adv_type'),
                    manufacturer_id=report.get('manufacturer_id'),
                    uuids=report.get('uuids', []),
                    first_seen=now,
                    last_seen=now,
                )
                self._seen[mac] = dev

                # Encola el dispositivo para que _dispatch_loop llame al callback
                self._event_queue.put(dev)

    def _register_classic_device(self, report: dict) -> None:
        """
        Registra o actualiza un dispositivo Bluetooth Clásico en el caché _seen.

        Funciona igual que _register_ble_device pero sin acumular UUIDs extra
        (los Clásicos solo dan nombre, no listas de UUIDs en cada Inquiry).
        """
        mac = report['mac']
        now = time.time()

        with self._lock:
            if mac in self._seen:
                # Dispositivo ya conocido: actualiza timestamp, RSSI y nombre
                dev           = self._seen[mac]
                dev.last_seen = now
                dev.rssi      = report['rssi'] if report['rssi'] is not None else dev.rssi
                if report.get('name'):
                    dev.name = report['name']

            else:
                # Dispositivo nuevo: crea el dataclass y lo añade al caché
                dev = BTDevice(
                    mac=mac,
                    name=report.get('name'),
                    rssi=report['rssi'],
                    bt_type='CLASSIC',
                    addr_type='public',
                    manufacturer_id=report.get('manufacturer_id'),
                    uuids=report.get('uuids', []),
                    first_seen=now,
                    last_seen=now,
                )
                self._seen[mac] = dev

                # Encola el dispositivo para que _dispatch_loop llame al callback
                self._event_queue.put(dev)

    # ── Hilo de callbacks ──────────────────────────────────────

    def _dispatch_loop(self) -> None:
        """
        Hilo separado que entrega BTDevice nuevos al callback on_device.

        Desacopla la detección (hilo HCI) de la notificación (callback del usuario).
        Esto evita que un callback lento bloquee la recepción de eventos HCI.
        Solo se ejecuta cuando hay algo en la cola; el timeout de 0.5s permite
        comprobar _running periódicamente aunque no lleguen dispositivos nuevos.
        """
        _dbg('DISPATCH_LOOP start')

        while self._running.is_set():
            try:
                # Espera hasta 0.5s por un nuevo BTDevice en la cola
                dev = self._event_queue.get(timeout=0.5)
            except queue.Empty:
                # No llegó nada en 0.5s: vuelve a comprobar _running
                continue

            # Si hay callback registrado, lo llama con el dispositivo nuevo
            if self.on_device:
                try:
                    self.on_device(dev)
                except Exception as e:
                    # El callback no debe poder tumbar el hilo de dispatch
                    _dbg(f'DISPATCH on_device excepción: {e!r}')

        _dbg('DISPATCH_LOOP terminado')
