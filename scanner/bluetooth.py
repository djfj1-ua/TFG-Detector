#!/usr/bin/env python3
"""
bluetoothPrueba.py — Scanner Bluetooth (BLE + Clásico) para TFG detección fraude académico.
Raspberry Pi 5, BCM43455, Raspberry Pi OS Bookworm ARM64.
"""

import ctypes
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────────────────────
# CONSTANTES HCI
# ──────────────────────────────────────────────────────────────

HCI_COMMAND_PKT = 0x01 # paquete de comando
HCI_EVENT_PKT = 0x04 # paquete de evento

# Códigos de evento HCI que nos interesan
HCI_EV_INQUIRY_COMPLETE = 0x01 # fin del período de Inquiry clásico
HCI_EV_INQUIRY_RESULT_RSSI = 0x22 # respuesta de Inquiry con RSSI (sin nombre)
HCI_EV_EXTENDED_INQUIRY = 0x2F # respuesta de Inquiry extendida (con nombre EIR)
HCI_EV_LE_META = 0x3E # evento contenedor de todos los subeventos BLE
HCI_LE_EV_ADV_REPORT = 0x02 # subevento dentro de LE_META: advertising report

# OGF (Opcode Group Field): agrupan comandos por categoría
OGF_LE_CTL = 0x08 # grupo de comandos LE Controller
OGF_LINK_CTL = 0x01 # grupo de comandos Link Control (Inquiry clásico)

# OCF (Opcode Command Field): identifican el comando concreto dentro del OGF
OCF_LE_SET_SCAN_PARAM = 0x000B # configurar parámetros del BLE scan
OCF_LE_SET_SCAN_ENABLE = 0x000C # activar o desactivar el BLE scan
OCF_INQUIRY = 0x0001 # lanzar un Inquiry Bluetooth clásico

TIPOS_ADV = {
    0: 'ADV_IND', # connectable undirected — el más común
    1: 'ADV_DIRECT', # connectable directed
    2: 'ADV_SCAN', # scannable undirected
    3: 'ADV_NONCONN', # non-connectable undirected
    4: 'SCAN_RSP', # respuesta a un scan request activo
}

# Códigos de tipo de las estructuras AD/EIR (formato TLV compartido por BLE y Clásico)
AD_NOMBRE_CORTO = 0x08 # nombre abreviado del dispositivo
AD_NOMBRE_COMPLETO = 0x09 # nombre completo del dispositivo
AD_POTENCIA_TX = 0x0A # potencia de transmisión en dBm
AD_UUID16_INC = 0x02 # lista incompleta de UUIDs de 16 bits
AD_UUID16_COMP = 0x03 # lista completa de UUIDs de 16 bits
AD_UUID128_INC = 0x06 # lista incompleta de UUIDs de 128 bits
AD_UUID128_COMP = 0x07 # lista completa de UUIDs de 128 bits
AD_FABRICANTE = 0xFF # datos específicos del fabricante (company ID + payload)

# ──────────────────────────────────────────────────────────────
# HCI FILTER
# ──────────────────────────────────────────────────────────────

class FiltroHCIKernel(ctypes.Structure):
    """
    Enseña el struct hci_filter del kernel Linux tal como es en ARM64.
    En ARM64 'unsigned long' ocupa 8 bytes, por lo que el struct mide 32 bytes.
    ctypes calcula el tamaño correcto según la plataforma.

    Campos:
      type_mask — bitmask de tipos de paquete HCI a dejar pasar
      event_mask — bitmask de códigos de evento HCI a dejar pasar (2 × 8 bytes)
      opcode — filtro opcional por opcode de comando (0 = sin filtro)
    """
    _fields_ = [
        ('type_mask', ctypes.c_ulong), # 8 bytes en ARM64
        ('event_mask', ctypes.c_ulong * 2), # 16 bytes: dos palabras de 8 bytes
        ('opcode', ctypes.c_uint16), # 2 bytes
    ]


def constructorFiltroHCI(*codigos_evento: int) -> bytes:
    """
    Construye el binario del struct hci_filter para aplicarlo al socket HCI RAW.
    Activa los bits correspondientes a cada evento que queremos recibir.
    """
    filtro = FiltroHCIKernel()

    # Activa el bit del tipo HCI_EVENT_PKT (0x04) para recibir eventos del controlador
    filtro.type_mask = 1 << HCI_EVENT_PKT

    for ev in codigos_evento:
        bit = ev & 31 # regla del kernel ARM64: siempre módulo 32, siempre word 0
        filtro.event_mask[0] |= 1 << bit

    return bytes(filtro)


# ──────────────────────────────────────────────────────────────
# MODELO DE DATOS
# ──────────────────────────────────────────────────────────────

@dataclass
class BTDevice:
    """
    Representa un dispositivo Bluetooth detectado (BLE o Clásico).
    Se actualiza en tiempo real cada vez que se recibe un nuevo paquete del mismo MAC.
    """
    mac:              str           # dirección MAC
    nombre:           Optional[str] # nombre del dispositivo (None si no se ha anunciado)
    rssi:             Optional[int] # potencia de señal recibida en dBm
    tipo:             str           # 'BLE' o 'CLASSIC'
    tipo_direccion:   str           # 'public' (fija) o 'random'
    tipo_advertising: Optional[str] = None  # tipo de advertising BLE
    id_fabricante:    Optional[int] = None  # company ID del fabricante (ej. 0x004C = Apple)
    uuids:            list          = field(default_factory=list)  # servicios anunciados
    primera_vez:      float         = field(default_factory=time.time)  # primer avistamiento
    ultima_vez:       float         = field(default_factory=time.time)  # último avistamiento

    @property
    def proximidad(self) -> str:
        """
        Clasifica la proximidad del dispositivo en tres zonas según el RSSI.

        Devuelve:
          'cerca'           — RSSI >= -85 dBm: el dispositivo está muy próximo
          'dentro del aula' — RSSI >= -95 dBm: está en el aula o pasillo contiguo
          'fuera'           — RSSI <  -95 dBm: está lejos, fuera del perímetro
          'desconocido'     — si aún no se ha recibido ningún RSSI
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

def parseoADStructure(datos: bytes) -> dict:
    """
    Parsea las estructuras AD (Advertising Data) o EIR (Extended Inquiry Response).

    Estructura de cada bloque:
      [0] longitud — número de bytes que siguen (incluye el byte de tipo)
      [1] tipo — código que identifica qué contiene el bloque
      [2:longitud] valor — datos del bloque (longitud-1 bytes)

    Devuelve un dict con las claves: 'nombre', 'potencia_tx', 'uuids', 'id_fabricante'.
    Los campos que no aparezcan en los datos quedan como None o lista vacía.
    """
    resultado: dict = {
        'uuids':         [],
        'id_fabricante': None,
        'nombre':        None,
        'potencia_tx':   None,
    }

    i = 0
    while i < len(datos):
        #Lee el byte de longitud actual
        longitud = datos[i]

        #Si longitud es igual a 0, se salta porque es el final del bloque
        if longitud == 0:
            i += 1
            continue

        if i + longitud >= len(datos):
            break

        #Saca el tipo y el valor del bloque
        tipo_ad  = datos[i + 1]
        valor_ad = datos[i + 2: i + 1 + longitud]

        #Pone el puntero en el siguiente bloque
        i += 1 + longitud

        # ── Nombre del dispositivo ──────────────────────────────
        if tipo_ad in (AD_NOMBRE_CORTO, AD_NOMBRE_COMPLETO):
            #Decodifica UTF-8 y elimina los nulos de relleno
            try:
                resultado['nombre'] = valor_ad.decode('utf-8', errors='replace').strip('\x00')
            except Exception:
                pass

        # ── Potencia de transmisión ─────────────────────────────
        elif tipo_ad == AD_POTENCIA_TX and len(valor_ad) >= 1:
            # TX Power es un int8 signed
            resultado['potencia_tx'] = int.from_bytes(valor_ad[:1], 'big', signed=True)

        # ── UUIDs de 16 bits ────────────────────────────────────
        elif tipo_ad in (AD_UUID16_INC, AD_UUID16_COMP):
            for j in range(0, len(valor_ad) - 1, 2):
                uuid16 = int.from_bytes(valor_ad[j:j+2], 'little')
                resultado['uuids'].append(f'{uuid16:04X}')

        # ── UUIDs de 128 bits ───────────────────────────────────
        elif tipo_ad in (AD_UUID128_INC, AD_UUID128_COMP):
            for j in range(0, len(valor_ad) - 15, 16):
                raw = valor_ad[j:j + 16][::-1]
                resultado['uuids'].append(raw.hex())

        # ── Datos del fabricante ────────────────────────────────
        elif tipo_ad == AD_FABRICANTE and len(valor_ad) >= 2:
            # Los primeros 2 bytes son el company ID (ej. 0x004C = Apple, 0x0006 = Microsoft)
            resultado['id_fabricante'] = int.from_bytes(valor_ad[:2], 'little')

    return resultado


def transformarMAC(raw: bytes) -> str:
    """
    Convierte una dirección MAC de 6 bytes en formato little-endian (como llega en HCI)
    a la cadena estándar XX:XX:XX:XX:XX:XX en mayúsculas.
    """
    # reversed() invierte el orden de bytes (de little-endian a big-endian)
    return ':'.join(f'{b:02X}' for b in reversed(raw))


# ──────────────────────────────────────────────────────────────
# COMANDOS HCI
# ──────────────────────────────────────────────────────────────

def comandoHCI(ogf: int, ocf: int, parametros: bytes = b'') -> bytes:
    """
    Construye un paquete HCI Command para enviar por el socket RAW.

    Formato del paquete HCI Command:
      [0] tipo_paquete = 0x01 (HCI_COMMAND_PKT)
      [1:3] opcode = (OGF << 10) | OCF, en little-endian
      [3] longitud_params = longitud de los parámetros
      [4:] parametros = parámetros del comando
    """
    opcode = (ogf << 10) | ocf

    return bytes([HCI_COMMAND_PKT]) + opcode.to_bytes(2, 'little') + bytes([len(parametros)]) + parametros


def parametroEscanerBLE() -> bytes:
    """
    Construye el comando HCI_LE_Set_Scan_Parameters (OGF=0x08, OCF=0x000B).

    Parámetros fijados:
      tipo_scan = 0x01 (activo): envía SCAN_REQ para obtener SCAN_RSP con más datos
      intervalo = 0x0200 = 512 × 0.625ms = 320ms
      ventana   = 0x0200 = 320ms (igual al intervalo -> escucha continuamente)
      tipo_dir_propia  = 0x00 (dirección pública del adaptador)
      politica_filtro  = 0x00 (aceptar todos los dispositivos)
    """
    parametros = (
        bytes([0x01]) +
        (0x0200).to_bytes(2, 'little') +
        (0x0200).to_bytes(2, 'little') +
        bytes([0x00, 0x00])
    )
    return comandoHCI(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAM, parametros)


def activarDesactivarEscanerBLE(activar: int, filtrar_dup: int = 0x00) -> bytes:
    """
    Construye el comando HCI_LE_Set_Scan_Enable (OGF=0x08, OCF=0x000C).
    Activa o desactiva el BLE scan previamente configurado.
    """
    return comandoHCI(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, bytes([activar, filtrar_dup]))


def cmdInquiry(duracion: int = 8) -> bytes:
    """
    Construye el comando HCI_Inquiry (OGF=0x01, OCF=0x0001).
    Inicia el proceso de descubrimiento de dispositivos Bluetooth Clásico (BR/EDR).

    Parámetros:
      LAP = 0x9E8B33 (GIAC — General Inquiry Access Code)
            Código estándar para discovery general de todos los dispositivos.
            Se transmite en little-endian.
      duracion       = unidades de 1.28s -> duracion=8 equivale a ~10.24 segundos
      num_respuestas = 0 -> sin límite de respuestas
    """
    parametros = b'\x33\x8B\x9E' + bytes([duracion, 0])
    return comandoHCI(OGF_LINK_CTL, OCF_INQUIRY, parametros)


# ──────────────────────────────────────────────────────────────
# SCANNER PRINCIPAL
# ──────────────────────────────────────────────────────────────

class BluetoothScanner:
    """
    Scanner Bluetooth que detecta dispositivos BLE y Clásico simultáneamente
    usando un único socket HCI RAW y un único hilo de captura.
    """

    def __init__(self):
        """Inicializa el scanner sin arrancarlo."""
        self._vistos: dict[str, BTDevice] = {}
        self._bloqueo = threading.Lock()

        self._activo = threading.Event()

        self._hilo:  Optional[threading.Thread] = None
        self._timer: Optional[threading.Timer]  = None

    # ── API pública ────────────────────────────────────────────

    def start(self) -> None:
        """
        Arranca el scanner lanzando el hilo de captura HCI.
        El hilo es daemon para que muera solo si el proceso principal termina.
        """
        self._activo.set()
        self._hilo = threading.Thread(
            target=self.bucleBLE, daemon=True, name='ble-loop'
        )
        self._hilo.start()

    def stop(self) -> None:
        """
        Detiene el scanner de forma ordenada:
          1. Limpia el Event -> los bucles while de los hilos salen en su próxima iteración
          2. Cancela el temporizador del Inquiry si estaba pendiente de disparar
        """
        self._activo.clear()

        if self._timer is not None:
            self._timer.cancel()

    @property
    def devices(self) -> list:
        """
        Devuelve una copia de la lista de dispositivos detectados hasta el momento.
        Usa el bloqueo para garantizar consistencia aunque el bucle esté actualizando la lista.
        """
        with self._bloqueo:
            return list(self._vistos.values())

    # ── Hilo único de captura ──────────────────────────────────

    def bucleBLE(self) -> None:
        """
        Hilo principal de captura. Es el único que lee del socket HCI RAW.
        Abre el socket, configura el filtro, activa el BLE scan, lanza el primer
        Inquiry y luego entra en un bucle indefinido hasta que stop() se llame.

        En caso de excepción no recuperable, termina.
        El bloque finally garantiza que el socket se cierra siempre.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
            sock.bind((0,))

            filtro = constructorFiltroHCI(
                HCI_EV_LE_META,             # advertising BLE
                HCI_EV_INQUIRY_RESULT_RSSI, # respuesta Inquiry con RSSI
                HCI_EV_EXTENDED_INQUIRY,    # respuesta Inquiry extendida
                HCI_EV_INQUIRY_COMPLETE,    # fin del Inquiry
            )
            sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, filtro)

            self.habilitarScaneoBLE(sock)
            self.lanzarInquiry(sock)
            sock.settimeout(1.0)

            while self._activo.is_set():
                try:
                    raw = sock.recv(4096)
                    self.procesarEventoHCI(raw, sock)
                except Exception:
                    continue

        except Exception:
            pass  # si el adaptador no está disponible, el hilo termina limpiamente

        finally:
            if sock is not None:
                try:
                    sock.send(activarDesactivarEscanerBLE(0))
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass

    # ── Gestión BLE scan ───────────────────────────────────────

    def habilitarScaneoBLE(self, sock: socket.socket) -> None:
        """
        Envía al adaptador los dos comandos necesarios para activar el BLE scan:
          1. HCI_LE_Set_Scan_Parameters — configura tipo, intervalo y ventana
          2. HCI_LE_Set_Scan_Enable — activa el scan con los parámetros anteriores
        El sleep de 50ms entre ambos da tiempo al firmware a procesar el primero.
        """
        sock.send(parametroEscanerBLE())

        time.sleep(0.05)

        # Activa el scan; filtrar_dup=0 para recibir todos los paquetes, incluso duplicados
        sock.send(activarDesactivarEscanerBLE(1, filtrar_dup=0))

    def deshabilitarScaneoBLE(self, sock: socket.socket) -> None:
        """
        Desactiva el BLE scan enviando HCI_LE_Set_Scan_Enable con activar=0.
        Se usa exclusivamente en busquedaCompleta para hacer el reset del firmware
        BCM43455, que entra en silencio al terminar el Inquiry.
        El sleep de 100ms da tiempo al firmware a procesar el disable.
        """
        try:
            sock.send(activarDesactivarEscanerBLE(0))
        except OSError:
            pass

        time.sleep(0.1)

    # ── Gestión Inquiry ────────────────────────────────────────

    def lanzarInquiry(self, sock: socket.socket) -> None:
        """
        Envía el comando HCI_Inquiry al adaptador e inicia el temporizador
        que detectará cuándo ha terminado.
        """

        if not self._activo.is_set():
            return

        try:
            sock.send(cmdInquiry(duracion=8))
        except OSError:
            return

        # Inicia el temporizador que disparará busquedaCompleta cuando el Inquiry deba haber terminado
        self._timer = threading.Timer(10.74, self.busquedaCompleta, args=[sock])
        self._timer.daemon = True
        self._timer.start()

    def busquedaCompleta(self, sock: socket.socket) -> None:
        """
        Callback del temporizador: se ejecuta ~10.74s después de lanzar el Inquiry.

        Realiza el ciclo de recuperación del firmware:
          1. Desactiva el BLE scan  -> el firmware sale del estado de silencio
          2. Reactiva el BLE scan   -> el adaptador vuelve a emitir advertising reports
          3. Espera 5s de BLE puro  -> temporizador para lanzar el siguiente Inquiry
        """
        # Si se ha pedido parar entre que se lanzó el temporizador y ahora, no hace nada
        if not self._activo.is_set():
            return

        self.deshabilitarScaneoBLE(sock)

        self.habilitarScaneoBLE(sock)

        self._timer = threading.Timer(5.0, self.lanzarInquiry, args=[sock])
        self._timer.daemon = True
        self._timer.start()

    # ── Procesado de eventos HCI ────────────────────────────────

    def procesarEventoHCI(self, raw: bytes, sock: socket.socket) -> None:
        """
        Punto de entrada de todos los paquetes HCI recibidos del socket.
        Valida la cabecera, identifica el tipo de evento y deriva al parser específico.
        """
        
        if len(raw) < 3:
            return

        if raw[0] != HCI_EVENT_PKT:
            return

        cod_evento = raw[1]

        if cod_evento == HCI_EV_LE_META:
            
            if len(raw) >= 4:
                subevento = raw[3]
            else:
                subevento = 0xFF
            if subevento == HCI_LE_EV_ADV_REPORT:
                
                self.parsearAdvertisingBLE(raw[4:])


        elif cod_evento == HCI_EV_INQUIRY_RESULT_RSSI:
            
            self.parsearInquiryRssi(raw[3:])


        elif cod_evento == HCI_EV_EXTENDED_INQUIRY:
            self.parsearInquiryExtendido(raw[3:])


    def parsearAdvertisingBLE(self, datos: bytes) -> None:
        """
        Parsea los datos de un LE Advertising Report.
        Un solo paquete puede contener varios informes consecutivos de la misma captura.

        Estructura de los datos:
          [0] num_informes — cuántos informes vienen en este paquete
          Por cada informe:
            [0] tipo_evento — tipo de advertising
            [1] tipo_dir — 0=público, 1=aleatorio
            [2:8] MAC — dirección en little-endian (6 bytes)
            [8] long_datos — longitud de los AD structures que siguen
            [9:9+N] datos_ad — N bytes de estructuras TLV
            [9+N] RSSI — int8 signed (último byte del informe)
        """
        if not datos:
            return

        # Número de informes incluidos en este paquete
        num_informes = datos[0]

        desplazamiento = 1  # puntero al inicio del primer informe
        for _ in range(num_informes):
            
            if desplazamiento + 9 > len(datos):
                break

            tipo_evento = datos[desplazamiento]
            tipo_dir    = datos[desplazamiento + 1]
            mac_bytes   = datos[desplazamiento + 2: desplazamiento + 8]
            long_datos  = datos[desplazamiento + 8]
            desplazamiento += 9  # avanza más allá de la cabecera

            if desplazamiento + long_datos > len(datos):
                break

            datos_ad = datos[desplazamiento: desplazamiento + long_datos]
            desplazamiento += long_datos

            rssi: Optional[int] = None
            if desplazamiento < len(datos):
                rssi = int.from_bytes(datos[desplazamiento:desplazamiento+1], 'big', signed=True)
                desplazamiento += 1

            mac = transformarMAC(mac_bytes)
            
            analizado = parseoADStructure(datos_ad)

            if tipo_dir:
                tipo_direccion = 'random'
            else:
                tipo_direccion = 'public'

            informe = {
                'mac':              mac,
                'rssi':             rssi,
                'tipo':             'BLE',
                'tipo_direccion':   tipo_direccion,
                'tipo_advertising': TIPOS_ADV.get(tipo_evento),
                'nombre':           analizado.get('nombre'),
                'id_fabricante':    analizado.get('id_fabricante'),
                'uuids':            analizado.get('uuids', []),
            }
            self.registrarDispositivoBLE(informe)

    # ── Parseo Inquiry Result with RSSI (0x22) ─────────────────

    def parsearInquiryRssi(self, datos: bytes) -> None:
        """
        Parsea el evento HCI_EV_INQUIRY_RESULT_RSSI (0x22).
        Contiene respuestas de dispositivos Clásicos que no han enviado EIR,
        por lo que solo tenemos MAC y RSSI (el nombre llega después con Extended Inquiry).

        Estructura de los datos:
          [0] num_resp — número de dispositivos en esta respuesta
          Por cada dispositivo (15 bytes fijos):
            [0:6]  BD_ADDR — MAC en little-endian
            [6] Page_Scan_Repetition_Mode — ignorado
            [7:9] Reserved — ignorado
            [9:12] Class_of_Device — ignorado
            [12:14] Clock_Offset — ignorado
            [14] RSSI — potencia de señal en dBm
        """
        if not datos:
            return

        num_resp = datos[0]  # número de respuestas en el paquete
        for i in range(num_resp):
            
            base = 1 + i * 15

            if base + 15 > len(datos):
                break

            mac_bytes = datos[base: base + 6]
            rssi      = int.from_bytes(datos[base + 14:base + 15], 'big', signed=True)
            mac       = transformarMAC(mac_bytes)

            # El nombre llegará más tarde en un Extended Inquiry Result, por ahora es None
            informe = {
                'mac':            mac,
                'rssi':           rssi,
                'tipo':           'CLASSIC',
                'tipo_direccion': 'public',
                'nombre':         None,
                'id_fabricante':  None,
                'uuids':          [],
            }
            self.registrarDispositivosClasicos(informe)

    # ── Parseo Extended Inquiry Result (0x2F) ──────────────────

    def parsearInquiryExtendido(self, datos: bytes) -> None:
        """
        Parsea el evento HCI_EV_EXTENDED_INQUIRY (0x2F).
        Siempre contiene exactamente 1 dispositivo. Incluye nombre y UUIDs en el EIR.

        Estructura del payload (255 bytes totales):
          [0] num_respuestas — ignorado
          [1:7] BD_ADDR — MAC en little-endian
          [7] Page_Scan_Repetition_Mode — ignorado
          [8] Reserved — ignorado
          [9:12] Class_of_Device — ignorado
          [12:14] Clock_Offset — ignorado
          [14] RSSI — potencia de señal dBm
          [15:255] datos EIR — nombre, UUIDs, etc.
        """

        if len(datos) < 15:
            return

        #datos[0] = num_respuestas (siempre 1, no se usa explícitamente)
        mac_bytes = datos[1:7]  # MAC del dispositivo
        rssi      = int.from_bytes(datos[14:15], 'big', signed=True)

        #Los datos EIR ocupan desde el byte 15 hasta el 255
        if len(datos) >= 255:
            datos_eir = datos[15:255]
        else:
            datos_eir = datos[15:]

        mac       = transformarMAC(mac_bytes)
        analizado = parseoADStructure(datos_eir)  # parsea nombre, UUIDs, etc.

        informe = {
            'mac':            mac,
            'rssi':           rssi,
            'tipo':           'CLASSIC',
            'tipo_direccion': 'public',
            'nombre':         analizado.get('nombre'),
            'id_fabricante':  analizado.get('id_fabricante'),
            'uuids':          analizado.get('uuids', []),
        }
        self.registrarDispositivosClasicos(informe)

    # ── Registro de dispositivos ───────────────────────────────

    def registrarDispositivoBLE(self, informe: dict) -> None:
        """
        Registra o actualiza un dispositivo BLE en el caché _vistos.

        Si la MAC ya existe: actualiza ultima_vez, rssi, nombre y
        acumula UUIDs e id_fabricante nuevos.
        Si es nueva: crea el BTDevice y lo añade al caché.

        Usa _bloqueo para proteger el acceso concurrente a _vistos desde múltiples hilos.
        """
        mac   = informe['mac']
        ahora = time.time()

        with self._bloqueo:
            if mac in self._vistos:
                disp = self._vistos[mac]
                disp.ultima_vez = ahora

                if informe['rssi'] is not None:
                    disp.rssi = informe['rssi']

                if informe.get('nombre'):
                    disp.nombre = informe['nombre']

                for u in informe.get('uuids', []):
                    if u not in disp.uuids:
                        disp.uuids.append(u)

                if informe.get('id_fabricante') is not None:
                    disp.id_fabricante = informe['id_fabricante']

            else:
                disp = BTDevice(mac=mac,nombre=informe.get('nombre'),rssi=informe['rssi'],tipo='BLE',tipo_direccion=informe.get('tipo_direccion', 'public'),tipo_advertising=informe.get('tipo_advertising'),id_fabricante=informe.get('id_fabricante'),uuids=informe.get('uuids', []),primera_vez=ahora,ultima_vez=ahora)
                self._vistos[mac] = disp

    def registrarDispositivosClasicos(self, informe: dict) -> None:
        """
        Registra o actualiza un dispositivo Bluetooth Clásico en el caché _vistos.

        Funciona igual que registrarDispositivoBLE pero sin acumular UUIDs extra.
        """
        mac   = informe['mac']
        ahora = time.time()

        with self._bloqueo:
            if mac in self._vistos:
                disp = self._vistos[mac]
                disp.ultima_vez = ahora
                if informe['rssi'] is not None:
                    disp.rssi = informe['rssi']

                if informe.get('nombre'):
                    disp.nombre = informe['nombre']

            else:
                disp = BTDevice(mac=mac,nombre=informe.get('nombre'),rssi=informe['rssi'],tipo='CLASSIC',tipo_direccion='public',id_fabricante=informe.get('id_fabricante'),uuids=informe.get('uuids', []),primera_vez=ahora,ultima_vez=ahora)
                self._vistos[mac] = disp
