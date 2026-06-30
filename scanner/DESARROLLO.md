# DESARROLLO — Sistema de detección de fraude académico

Scanner Bluetooth (BLE + Clásico) y Wi-Fi 802.11 para el TFG de detección de fraude académico.  
Hardware: Raspberry Pi 5 · BCM43455 (wlan0 AP) · Alfa AWUS036ACHM MT7612U (wlan1 monitor) · Raspberry Pi OS Bookworm 64-bit ARM64 · Kernel 6.x

> **Restricción legal:** El sistema NO inhibe señales (ilegal bajo Ley 11/2022 española).  
> Solo monitorización pasiva del espectro electromagnético. La interfaz solo escucha.

---

## Índice

1. [Scanner Bluetooth](#1-scanner-bluetooth--bluetoothpy)
2. [Scanner Wi-Fi](#2-scanner-wi-fi--wifi_capturepy)
3. [API REST](#3-api-rest--webapypy)
4. [Aplicación móvil Flutter](#4-aplicación-móvil-flutter)
5. [Despliegue e integración del sistema](#5-despliegue-e-integración-del-sistema)

---

# 1. Scanner Bluetooth — `bluetooth.py`

Scanner Bluetooth (BLE + Clásico) para el TFG de detección de fraude académico.  
Hardware: Raspberry Pi 5 · BCM43455 · Raspberry Pi OS Bookworm 64-bit ARM64 · Kernel 6.x

---

## Objetivo

Detectar dispositivos Bluetooth en el entorno de un aula para identificar presencia no
declarada durante exámenes. El scanner debe funcionar de forma continua e indefinida,
detectando simultáneamente dispositivos BLE y Bluetooth Clásico (BR/EDR) sin usar
librerías externas (sin bluepy, bleak, PyBluez, subprocess ni hcitool).

---

## Restricciones técnicas

- Solo sockets HCI RAW: `AF_BLUETOOTH / BTPROTO_HCI`
- Parseo byte a byte con `struct.unpack`, sin librerías de parseo externas
- Un único socket para BLE y Clásico simultáneamente
- Sin dependencias externas de Bluetooth

---

## Arquitectura final

### Un solo hilo, un solo socket

El chip BCM43455 recibe eventos BLE e Inquiry clásico por el mismo socket.
El hilo `_ble_loop` abre el socket, aplica el filtro HCI, activa el BLE scan
y lanza el primer Inquiry. A partir de ahí el bucle `recv()` recibe todos los
eventos de ambos protocolos.

### Ciclo de operación

```
t=0s      BLE scan activado (scan_type=1 activo, interval/window=0x0200)
t=0s      Primer Inquiry lanzado (duration=8 → ~10.24s)
t=0-10s   Recepción simultánea: BLE ADV reports + Extended Inquiry Results
t=10.74s  Timer temporal dispara _on_inquiry_done
t=10.74s  BLE scan desactivado + reactivado (reset firmware BCM43455)
t=10.74s  Timer 5s para próximo Inquiry
t=15.74s  Timer dispara _launch_inquiry → nuevo Inquiry
... repite indefinidamente
```

### Hilos

| Hilo | Nombre | Función |
|------|--------|---------|
| `_ble_loop` | `ble-loop` | Único hilo de captura. Socket RAW, recv loop, parseo HCI |
| `_dispatch_loop` | `dispatch` | Entrega BTDevice al callback `on_device` desde cola interna |

---

## Filtro HCI — hallazgo crítico ARM64 Bookworm

El `struct hci_filter` del kernel Linux en ARM64 se construye con `ctypes.c_ulong`
(8 bytes en 64-bit), dando un struct de 32 bytes total:

```python
class _KernelHciFilter(ctypes.Structure):
    _fields_ = [
        ('type_mask',  ctypes.c_ulong),      # 8 bytes
        ('event_mask', ctypes.c_ulong * 2),  # 16 bytes
        ('opcode',     ctypes.c_uint16),     # 2 bytes
    ]
```

**Regla verificada empíricamente en BCM43455 / kernel 6.x ARM64:**  
El kernel usa `bit = event_code & 31` dentro de **`event_mask[0]` para todos los
eventos**, independientemente de si el código supera 31. No se distribuye entre
`event_mask[0]` y `event_mask[1]` según el valor del código.

| Evento | Código | Bit (& 31) | Máscara resultante |
|--------|--------|------------|--------------------|
| `HCI_EV_INQUIRY_COMPLETE` | `0x01` | 1 | `0x0000000000000002` |
| `HCI_EV_INQUIRY_RESULT_RSSI` | `0x22` | 2 | `0x0000000000000004` |
| `HCI_EV_EXTENDED_INQUIRY` | `0x2F` | 15 | `0x0000000000008000` |
| `HCI_EV_LE_META` | `0x3E` | 30 | `0x0000000040000000` |
| **Combinado** | | | **`0x0000000040008006`** |

**Error cometido durante el desarrollo:** se intentó usar `word = (ev >> 5) & 1`
para distribuir entre `event_mask[0]` y `event_mask[1]`. Esto colocó el bit de
`HCI_EV_LE_META` (0x3E) en `event_mask[1]`, rompiendo completamente la recepción
de eventos BLE. El filtro correcto usa siempre `event_mask[0]`.

---

## Comportamiento del firmware BCM43455 — hallazgo crítico

### Problema: silencio total tras fin del Inquiry

Durante el desarrollo se observó que pasados ~10 segundos del inicio, el scanner
dejaba de recibir cualquier evento. El debug log reveló:

```
[  +0.553s]  Inquiry enviado
[  +0.772s]  EXTENDED_INQUIRY_RESULT  → Redmi Buds 3 Pro
[  +2.428s]  EXTENDED_INQUIRY_RESULT  → Samsung TV
[  +1.5s - +10.7s]  BLE ADV reports continuos
[  +10.742s]  Último evento BLE recibido
                ← silencio total durante 36 segundos →
[  +46.871s]  stop() por usuario
```

El Inquiry tenía duración 8 × 1.28s ≈ 10.24s, arrancando en +0.553s debía
completar en +10.79s. Los eventos se detienen exactamente en ese momento.

### Causa raíz: dos problemas encadenados

**1. `HCI_EV_INQUIRY_COMPLETE` (0x01) nunca llega al socket compartido**

El contador `Inq complete: 0` durante toda la sesión lo confirma. El kernel
BCM43455 no entrega este evento a un socket que escucha BLE y Clásico
simultáneamente. En arquitecturas de doble socket (como `bluetooth.py`) sí llega
al socket dedicado al Inquiry.

**2. El firmware silencia todos los eventos al acabar el Inquiry**

Cuando el Inquiry termina, el BCM43455 deja de emitir cualquier evento HCI,
incluyendo los BLE advertising reports. El firmware no recupera el estado del BLE
scan por sí solo. Necesita un reset explícito (disable + enable del BLE scan)
para volver a emitir eventos.

### Hipótesis descartada

> *"El firmware BCM43455 gestiona internamente el BLE scan durante el Inquiry y lo
> recupera solo cuando el Inquiry termina."*

Esta hipótesis fue **descartada por los datos del debug**. El firmware NO recupera
el BLE scan automáticamente. El reset es obligatorio.

### Solución implementada

Como `INQUIRY_COMPLETE` no llega, no se puede usar ese evento como trigger.
Se usa un **timer temporal basado en la duración conocida del Inquiry**:

```python
# En _launch_inquiry():
sock.send(cmd_inquiry(duration=8))
# 8 × 1.28s + 0.5s margen = 10.74s
self._inquiry_timer = threading.Timer(10.74, self._on_inquiry_done, args=[sock])
self._inquiry_timer.start()

# En _on_inquiry_done():
self._disable_ble_scan(sock)   # reset firmware BCM43455
self._enable_ble_scan(sock)
# 5s de BLE puro antes del siguiente Inquiry
self._inquiry_timer = threading.Timer(5.0, self._launch_inquiry, args=[sock])
self._inquiry_timer.start()
```

---

## Parseo HCI — formato de paquetes

### Paquete HCI Event (todos los eventos)
```
[0]   packet_type  = 0x04 (HCI_EVENT_PKT)
[1]   event_code
[2]   parameter_length
[3:]  parameters
```

### LE Advertising Report (event=0x3E, subevent=0x02)
```
raw[3]   = subevent (0x02)
raw[4]   = num_reports
Por cada report:
  [0]    event_type  (0=ADV_IND, 1=ADV_DIRECT, 2=ADV_SCAN, 3=ADV_NONCONN, 4=SCAN_RSP)
  [1]    addr_type   (0=público, 1=aleatorio)
  [2:8]  MAC little-endian
  [8]    data_length
  [9:9+N] AD structures
  [final] RSSI (int8 signed)
```

### Extended Inquiry Result (event=0x2F)
```
params[0]     = num_responses (siempre 1)
params[1:7]   = BD_ADDR little-endian
params[7]     = Page_Scan_Repetition_Mode
params[8]     = Reserved
params[9:12]  = Class_of_Device
params[12:14] = Clock_Offset
params[14]    = RSSI (int8 signed)
params[15:255]= EIR data (240 bytes, formato TLV igual que AD structures BLE)
```

### Inquiry Result with RSSI (event=0x22)
```
params[0]     = num_responses
Por cada respuesta (15 bytes):
  [0:6]   BD_ADDR little-endian
  [6]     Page_Scan_Repetition_Mode
  [7:9]   Reserved
  [9:12]  Class_of_Device
  [12:14] Clock_Offset
  [14]    RSSI (int8 signed)
```

### AD / EIR structures (formato TLV compartido BLE y Clásico)
```
[0]        length (incluye type, no incluye este byte)
[1]        type
[2:length] value
```
Tipos procesados: `0x08/0x09` nombre, `0x0A` TX power, `0x02/0x03` UUID16,
`0x06/0x07` UUID128, `0xFF` manufacturer specific.

---

## Comandos HCI construidos manualmente

```python
# HCI_LE_Set_Scan_Parameters (OGF=0x08, OCF=0x000B)
# scan_type=0x01 (activo), interval=0x0200, window=0x0200, own_addr=0x00, filter=0x00
struct.pack('<BHHBB', 0x01, 0x0200, 0x0200, 0x00, 0x00)

# HCI_LE_Set_Scan_Enable (OGF=0x08, OCF=0x000C)
bytes([enable, filter_dup])   # enable: 0x01=on, 0x00=off

# HCI_Inquiry (OGF=0x01, OCF=0x0001)
# LAP=0x9E8B33 (GIAC), duration=8 (×1.28s ≈ 10s), num_responses=0
b'\x33\x8B\x9E' + struct.pack('<BB', 8, 0)

# Opcode = (OGF << 10) | OCF
# Paquete = struct.pack('<BHB', 0x01, opcode, len(params)) + params
```

---

## Modelo de datos — BTDevice

```python
@dataclass
class BTDevice:
    mac: str                    # XX:XX:XX:XX:XX:XX mayúsculas
    name: Optional[str]
    rssi: Optional[int]         # dBm
    bt_type: str                # 'BLE' | 'CLASSIC'
    addr_type: str              # 'public' | 'random'
    adv_type: Optional[str]     # solo BLE: ADV_IND, SCAN_RSP, etc.
    manufacturer_id: Optional[int]
    uuids: list
    first_seen: float           # timestamp Unix
    last_seen: float

    @property
    def proximity(self) -> str:
        # rssi >= -85 → 'cerca'            (dentro del aula)
        # rssi >= -95 → 'dentro del aula'  (pasillo o adyacente)
        # rssi <  -95 → 'fuera'            (lejos del perímetro)
```

---

## Filtrado de visualización

### Criterios de visibilidad

Los dispositivos se almacenan internamente en cuanto se detectan, pero solo
aparecen en pantalla si cumplen **ambas** condiciones simultáneamente:

1. **Tienen información identificativa** — al menos uno de estos campos no está vacío:
   - `name` (nombre del dispositivo)
   - `manufacturer_id` (company ID del fabricante)
   - `uuids` (lista de servicios anunciados)

   Esto filtra paquetes que solo llevan MAC + RSSI sin ningún dato útil para
   identificar al propietario del dispositivo.

2. **Han emitido en los últimos 20 segundos** — `last_seen` dentro del umbral:
   ```python
   (time.time() - d.last_seen) <= 20
   ```
   Los dispositivos que dejan de emitir desaparecen de la tabla pasados 20 s.
   Si vuelven a emitir, reaparecen automáticamente.

---

## Modelo de proximidad Bluetooth

| Zona | RSSI | Significado |
|------|------|-------------|
| `cerca` | ≥ -85 dBm | El dispositivo está dentro del aula |
| `dentro del aula` | ≥ -95 dBm | Pasillo inmediato o aula adyacente |
| `fuera` | < -95 dBm | Lejos del perímetro |

---

# 2. Scanner Wi-Fi — `wifi_capture.py`

Scanner 802.11 en modo monitor para detección de dispositivos inalámbricos durante exámenes.  
Hardware: Raspberry Pi 5 · Alfa AWUS036ACHM (MT7612U) en `wlan1` · modo monitor

---

## Objetivo

Detectar dispositivos Wi-Fi presentes en el entorno de un aula capturando frames de
gestión 802.11 sobre la interfaz `wlan1` en modo monitor. Los frames de interés son:

| Subtipo | Nombre | Por qué es relevante |
|---------|--------|----------------------|
| 0x04 | Probe Request | Un dispositivo busca redes activamente. Revela presencia aunque no haya AP |
| 0x08 | Beacon | Un AP (o hotspot móvil) anuncia su red periódicamente |
| 0x00 | Association Request | Un dispositivo intenta unirse a una red |
| 0x05 | Probe Response | Respuesta de un AP a un Probe Request |
| 0x0B | Authentication | Inicio del handshake de autenticación |
| 0x0C | Deauthentication | Cierre de sesión (útil para detectar ataques o reconexiones) |

Los frames de datos (`type=0x02`) y control (`type=0x01`) se descartan: no aportan
información útil para identificar dispositivos y saturarían el procesado.

---

## Restricciones técnicas

- Sin Scapy ni ninguna librería de parseo externa
- Todo parseo byte a byte con `struct.unpack` y manipulación directa de `bytes`
- Python 3 estándar únicamente
- `subprocess` permitido **solo** para operaciones de gestión del driver (`iw dev wlan1 set channel N`), nunca para parseo de paquetes

---

## Preparación del adaptador

La interfaz `wlan1` debe estar en modo monitor antes de ejecutar el scanner.
En producción esto lo hace la API automáticamente al recibir `POST /api/start`.
Para pruebas manuales:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
```

Para verificar que está en modo monitor:

```bash
iw dev wlan1 info
# Debe mostrar: type monitor
```

---

## Arquitectura

### Tres hilos, un socket

```
┌─────────────────────────────────────────────────────────────────┐
│  AF_PACKET / SOCK_RAW / ETH_P_ALL  ←  wlan1 (modo monitor)     │
│                                                                  │
│  ┌──────────────┐   raw bytes   ┌──────────────────────────┐    │
│  │  wifi-cap    │ ─────────────▶│  _handle_frame()         │    │
│  │  (captura)   │               │  RadioTap → 802.11 → IEs │    │
│  └──────────────┘               └────────────┬─────────────┘    │
│                                              │ WifiDevice (nuevo)│
│  ┌──────────────┐               ┌────────────▼─────────────┐    │
│  │  wifi-hop    │               │  wifi-dispatch           │    │
│  │  (hopping)   │               │  cola → on_device()      │    │
│  └──────────────┘               └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

| Hilo | Nombre | Función |
|------|--------|---------|
| `_capture_loop` | `wifi-cap` | Abre el socket AF_PACKET, recibe frames en bruto y llama a `_handle_frame` |
| `_hop_loop` | `wifi-hop` | Cambia el canal de `wlan1` periódicamente mediante `iw` |
| `_dispatch_loop` | `wifi-dispatch` | Desencola dispositivos nuevos y los entrega al callback `on_device` |

### Por qué el hopper vive en hilo separado

El `recv()` del hilo de captura bloquea hasta que llega un frame (timeout 1 s).
Si el hopper viviera ahí, el cambio de canal se retrasaría hasta el próximo frame
o hasta el timeout, rompiendo la cadencia en canales silenciosos.

### Ciclo de operación

```
t = 0 s      start() lanza los tres hilos
t = 0 s      wifi-hop cambia a CH 1, anota current_channel = 1
t = 0-200ms  wifi-cap captura todos los frames del CH 1
t = 200ms    wifi-hop cambia a CH 2, anota current_channel = 2
...
t = 2.6 s    un barrido completo de 13 canales 2.4 GHz
... repite indefinidamente
```

---

## Protocolo 802.11 en modo monitor — estructura de trama

En modo monitor, el driver mac80211 antepone un header **RadioTap** a cada frame
capturado del aire antes de entregarlo al socket. La trama completa recibida es:

```
┌──────────────────┬──────────────────────┬──────────────────┐
│  RadioTap header │  Cabecera MAC 802.11 │  Cuerpo del frame│
│  (variable)      │  (24 bytes fijos)    │  (IEs, datos...) │
└──────────────────┴──────────────────────┴──────────────────┘
```

---

## Parseo RadioTap

El header RadioTap contiene metadatos de RF que el driver añade:

```
[0]    revision  = 0 (siempre)
[1]    pad       = 0 (relleno)
[2:4]  length    — tamaño total del header (LE); es el offset al frame 802.11
[4:8]  present   — bitmask LE con los campos que están presentes
                   bit 31 = 1 → hay otra palabra present encadenada
campos a continuación, en orden de bit ascendente
```

Campos extraídos (los demás se saltan):

| Bit | Campo | Tamaño | Uso |
|-----|-------|--------|-----|
| 1 | Flags | 1 B | Bit 4 = FCS presente al final del frame (hay que recortar 4 bytes) |
| 3 | Channel | 4 B | Primeros 2: frecuencia en MHz (u16 LE); conversión a canal: `(freq - 2407) // 5` para 2.4 GHz |
| 5 | dBm Antenna Signal | 1 B | RSSI en dBm (int8 signed) |

**Regla de alineación:** Cada campo se alinea a su alineación natural medida
desde el byte **0 del header RadioTap** (= byte 0 del raw recibido), no desde
el inicio de los campos.

---

## Parseo cabecera MAC 802.11

La cabecera de un Management Frame siempre tiene 24 bytes fijos:

```
[0:2]   Frame Control:
          byte 0 — bits 0-1: Protocol Version (00)
                   bits 2-3: Type    (00=Mgmt, 01=Ctrl, 10=Data)
                   bits 4-7: Subtype (04=Probe Req, 08=Beacon, etc.)
          byte 1 — bit 6: Protected Frame (cuerpo cifrado con MFP)
[2:4]   Duration/ID
[4:10]  Addr1 — Destination
[10:16] Addr2 — Source (transmisor) ← identificador del dispositivo
[16:22] Addr3 — BSSID
[22:24] Sequence Control
```

Tras los 24 bytes fijos, cada subtipo tiene un bloque de **campos fijos propios**
antes de que empiecen los Information Elements:

| Subtipo | Nombre | Campos fijos | Bytes |
|---------|--------|--------------|-------|
| 0x00 | ASSOC_REQ | Capability + Listen Interval | 4 |
| 0x01 | ASSOC_RESP | Capability + Status Code + Assoc ID | 6 |
| 0x04 | PROBE_REQ | (ninguno) | 0 |
| 0x05 | PROBE_RESP | Timestamp + Beacon Interval + Capability | 12 |
| 0x08 | BEACON | Timestamp + Beacon Interval + Capability | 12 |
| 0x0B | AUTH | Algorithm + Auth Seq + Status Code | 6 |
| 0x0C | DEAUTH | Reason Code | 2 |

Por tanto, el offset real al inicio de los IEs es:

```python
body_offset = 24 + _FIXED_FIELDS_SIZE.get(subtype, 0)
```

---

## Bug crítico encontrado durante el desarrollo: `body_offset` incorrecto

### Síntoma

Los Beacons siempre mostraban `ssid=''` (wildcard) en lugar del SSID real del AP.
Las redes con nombre aparecían como si estuvieran buscando cualquier red.

### Causa

`body_offset` estaba hardcodeado a 24 para todos los subtipos. En un Beacon,
el bloque de 12 bytes de campos fijos empieza en el byte 24:

```
bytes 24-31: Timestamp (8 bytes, u64) — primeros bytes: 0x00 0x00 …
```

El parseo de IEs con `body_offset = 24` leía el campo Timestamp como si fuera
el primer IE:
- `tag = 0x00` → `IE_SSID`
- `length = 0x00` → longitud cero = **wildcard SSID**

El resultado era que cualquier Beacon era clasificado como wildcard probe.

### Fix

Añadir `_FIXED_FIELDS_SIZE` y calcular el offset real:

```python
_FIXED_FIELDS_SIZE = {
    0x00: 4, 0x01: 6, 0x04: 0, 0x05: 12, 0x08: 12, 0x0B: 6, 0x0C: 2
}
body_offset = 24 + _FIXED_FIELDS_SIZE.get(subtype, 0)
```

Descubierto al construir frames de prueba sintéticos antes de probar en hardware real.

---

## Parseo Information Elements (IEs)

Los IEs siguen el formato TLV, idéntico a los AD structures de Bluetooth:

```
[0]        Tag Number  — tipo del elemento
[1]        Tag Length  — bytes de valor (sin incluir los 2 bytes de cabecera)
[2:2+len]  Value
```

IEs procesados:

| Tag | Nombre | Uso |
|-----|--------|-----|
| `0x00` | SSID | Nombre de la red. `length=0` → wildcard (el dispositivo acepta cualquier red) |
| `0x03` | DS Parameter Set | Canal en el que opera el AP (1 byte). Más preciso que el canal del RadioTap |
| `0x30` | RSN | Presence → WPA2 o WPA3 activo |
| `0xDD` | Vendor Specific | Si OUI = `00:50:F2` + tipo `0x01` → WPA1 (anterior a RSN) |

### SSID wildcard vs SSID ausente

```
ssid = ''    → IE_SSID presente con length=0 (Probe Request sin destino concreto)
ssid = None  → IE_SSID no está en el frame
ssid = str   → SSID conocido
```

### Canal IE_DS_PARAM vs canal RadioTap

El canal del RadioTap refleja en qué canal estaba sintonizado el receptor en el
momento de la captura (puede diferir del canal real del AP si la interfaz cambió
de canal justo antes). El `IE_DS_PARAM` contiene el canal en el que el AP opera
realmente. Se usa `IE_DS_PARAM` cuando está disponible, con RadioTap como fallback:

```python
channel = ies.get('channel') or rt.get('channel')
```

---

## Channel hopping

### Por qué es necesario

Una interfaz 802.11 en modo monitor solo escucha **un canal a la vez**. Sin hopping,
solo se detectan dispositivos en el canal inicial. En la primera prueba sin hopping
solo aparecieron dispositivos en los canales 1 y 2.

### Por qué solo 2.4 GHz

- Los Probe Requests (el frame más revelador) se envían siempre en 2.4 GHz independientemente del modo del dispositivo.
- Con 13 canales el ciclo completo dura 2.6 s; añadir los 21 canales 5 GHz lo sube a 6.8 s, reduciendo la probabilidad de captura por canal.
- Los canales DFS de 5 GHz son silenciados silenciosamente por el driver MT7612U sin lanzar error.
- Las señales 2.4 GHz tienen mejor penetración de paredes, relevante en entornos de aula.

### Implementación

Un hilo dedicado (`wifi-hop`) cicla por todos los canales mediante `itertools.cycle`.
El cambio de canal se hace con `iw`:

```bash
iw dev wlan1 set channel <N>
```

Llamado desde Python mediante `subprocess.run` con timeout de 2 s. Los errores
(canales DFS no soportados, permisos) se silencian y el hopper sigue al siguiente.

El dwell (tiempo en cada canal) usa incrementos de 50 ms en lugar de un único
`sleep(hop_interval)` para poder responder a `stop()` rápidamente:

```python
deadline = time.monotonic() + self._hop_interval
while self._running.is_set() and time.monotonic() < deadline:
    time.sleep(0.05)
```

### Canales configurados

```python
_CHANNELS_2GHZ = list(range(1, 14))    # 13 canales, normativa europea
```

Con `hop_interval = 0.20 s` (defecto) un barrido completo de 2.4 GHz dura 2.6 s.

### Resultado en hardware real

| Prueba | Canales visibles | Dispositivos |
|--------|-----------------|--------------|
| Sin hopping | 1, 2 | 5 |
| Con hopping (hop_interval=0.20s) | 1, 2, 3, 4, 7, 10, 11, 13 | 15 |

---

## Modelo de datos — WifiDevice

```python
@dataclass
class WifiDevice:
    mac:          str            # XX:XX:XX:XX:XX:XX — dirección transmisora (addr2)
    ssid:         Optional[str]  # '' = wildcard, None = no visto, str = SSID conocido
    rssi:         Optional[int]  # dBm (negativo)
    channel:      Optional[int]  # canal 802.11
    frequency:    Optional[int]  # frecuencia en MHz
    frame_type:   str            # tipo del último frame: BEACON, PROBE_REQ, etc.
    addr_type:    str            # 'random' si MAC locally-administered, 'public' si OUI real
    is_protected: bool           # True si RSN IE o WPA IE detectado (acumulativo)
    manufacturer: Optional[str]  # fabricante por OUI; None si MAC aleatoria o desconocido
    first_seen:   float          # timestamp Unix
    last_seen:    float

    @property
    def proximity(self) -> str:
        # rssi >= -85 dBm → 'cerca'           (dentro del aula)
        # rssi >= -95 dBm → 'dentro del aula' (pasillo o adyacente)
        # rssi <  -95 dBm → 'fuera'           (lejos del perímetro)
        # rssi is None    → 'desconocido'
```

---

## Lookup OUI — fabricante

Los primeros 3 bytes de una MAC pública (no aleatoria) identifican al fabricante
según la base de datos IEEE. Se usa para mostrar "Apple", "Samsung", "Xiaomi", etc.

### Fuente de datos

1. Fichero IEEE completo (~6 MB, >50.000 entradas):
   ```bash
   sudo apt install ieee-data   # → /usr/share/ieee-data/oui.txt
   # O descarga manual:
   wget -O scanner/oui.txt https://standards-oui.ieee.org/oui/oui.txt
   ```
2. Tabla de reserva embebida (`_OUI_FALLBACK`): ~57 entradas con las marcas más
   frecuentes en un aula universitaria española (Apple, Samsung, Xiaomi, Huawei,
   Google, OPPO, Motorola, Sony, LG, Raspberry Pi).

`_load_oui_db()` se llama una sola vez al importar el módulo. Si no encuentra
ningún fichero IEEE, devuelve la tabla de reserva.

### MACs aleatorias (`[R]`)

El bit 1 (valor `0x02`) del primer byte de la MAC indica dirección
**locally-administered**: asignada localmente, no por el IEEE. Los teléfonos
modernos la usan en Probe Requests para evitar el rastreo.

Consecuencias:
- El OUI de una MAC aleatoria no identifica a ningún fabricante real.
- `manufacturer` se deja a `None` y `addr_type = 'random'`.
- En la tabla se muestra `[R]` en lugar del fabricante.

**Distinción importante:** algunos routers también ponen el bit locally-administered
en BSSIDs virtuales (para crear interfaces virtuales de un mismo AP físico). En ese
caso `[R]` aparece en un Beacon, no en un Probe Request — no es privacidad del
cliente sino una técnica del firmware del router.

---

## Modelo de proximidad Wi-Fi

Igual que en Bluetooth, se usan tres zonas calibradas para aula estándar:

| Zona | RSSI | Significado |
|------|------|-------------|
| `cerca` | ≥ -85 dBm | El dispositivo está dentro del aula |
| `dentro del aula` | ≥ -95 dBm | Pasillo inmediato o aula adyacente |
| `fuera` | < -95 dBm | Lejos del perímetro |

---

## Parámetros de `WifiScanner`

```python
WifiScanner(
    iface        = 'wlan1',   # interfaz en modo monitor
    on_device    = None,      # callback(WifiDevice) llamado al detectar dispositivo nuevo
    hop_interval = 0.20,      # segundos de permanencia por canal
    scan_5ghz    = False,     # si True, añade los 21 canales 5 GHz al ciclo
)
```

---

# 3. API REST — `web/api.py`

La API REST es la capa de comunicación entre los scanners Python y la aplicación
móvil Flutter. Se ejecuta como servicio systemd y arranca automáticamente con la Pi.

---

## Tecnología

- **Flask** (Python): servidor HTTP ligero, sin dependencias pesadas
- **Puerto**: 5000 sobre `0.0.0.0` (todas las interfaces)
- **Formato**: JSON en todos los endpoints
- **Concurrencia**: threading.Lock para acceso seguro a los scanners desde múltiples peticiones

---

## Endpoints

### `POST /api/start`

Pone `wlan1` en modo monitor y arranca `BluetoothScanner` + `WifiScanner`.

**Idempotente:** si ya estaba escaneando, devuelve `ok: true` sin relanzar los scanners
(evita el error "ya está escaneando" que se producía al abrir la app con la Pi ya activa).

```json
// Respuesta OK (nueva sesión)
{ "ok": true }

// Respuesta OK (ya estaba activo)
{ "ok": true, "msg": "Ya estaba escaneando" }

// Error: no se pudo poner wlan1 en monitor
{ "ok": false, "msg": "No se pudo poner wlan1 en modo monitor" }  // HTTP 500
```

Secuencia interna:
1. `ip link set wlan1 down`
2. `iw dev wlan1 set type monitor`
3. `ip link set wlan1 up`
4. Instanciar y arrancar `BluetoothScanner()` y `WifiScanner()`

---

### `POST /api/stop`

Para los scanners y restaura `wlan1` a modo managed.

**Idempotente:** si ya estaba parado, devuelve `ok: true`.

```json
{ "ok": true }
```

Secuencia interna:
1. `bt_scanner.stop()` + `wifi_scanner.stop()`
2. `ip link set wlan1 down`
3. `iw dev wlan1 set type managed`
4. `ip link set wlan1 up`

---

### `GET /api/status`

Estado actual del sistema. La app lo consulta al arrancar para sincronizarse con la Pi.

```json
{
  "scanning": true,
  "uptime": 142,
  "current_channel": 7,
  "wifi":      { "total": 12, "active": 5 },
  "bluetooth": { "total": 8,  "active": 3 }
}
```

- `uptime`: segundos desde que se llamó a `/api/start`
- `current_channel`: canal 2.4 GHz en el que está sintonizado `wlan1` en este momento
- `active`: dispositivos vistos en los últimos 20 s
- `total`: todos los dispositivos de la sesión

---

### `GET /api/devices`

Dispositivos **activos** (vistos en los últimos 20 s). La app lo llama cada 3 s para
actualizar el sonar en tiempo real.

```json
{
  "wifi": [
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "ssid": "MiMovil",
      "rssi": -62,
      "channel": 6,
      "frequency": 2437,
      "frame_type": "PROBE_REQ",
      "manufacturer": "Apple",
      "proximity": "cerca",
      "first_seen": 1719700000,
      "last_seen": 1719700045,
      "seconds_ago": 2
    }
  ],
  "bluetooth": [
    {
      "mac": "11:22:33:44:55:66",
      "name": "AirPods Pro",
      "rssi": -75,
      "bt_type": "BLE",
      "addr_type": "public",
      "manufacturer_id": 76,
      "uuids": [],
      "proximity": "dentro del aula",
      "first_seen": 1719700010,
      "last_seen": 1719700044,
      "seconds_ago": 3
    }
  ]
}
```

Los resultados están ordenados por RSSI descendente (señal más fuerte primero).

**Filtro Bluetooth adicional:** solo se incluyen dispositivos que tengan al menos
`name`, `manufacturer_id` o `uuids` — descarta paquetes MAC+RSSI vacíos.

---

### `GET /api/history`

Todos los dispositivos detectados en la sesión **sin filtro de tiempo**. La app lo
llama al pulsar "Parar" para construir la pantalla de historial.

```json
{
  "wifi": [ ... ],
  "bluetooth": [ ... ],
  "session_duration": 847
}
```

- `session_duration`: duración total de la sesión en segundos

---

### `GET /api/devices/wifi` y `GET /api/devices/bluetooth`

Subconjuntos individuales. Misma estructura que el array correspondiente de `/api/devices`.
Disponibles para consultas específicas.

---

## Gestión del modo monitor

La API gestiona el ciclo de vida del adaptador `wlan1` mediante `subprocess`:

```python
def _set_monitor_mode() -> bool:
    subprocess.run(['ip',  'link', 'set',  _IFACE, 'down'],         check=True, ...)
    subprocess.run(['iw',  'dev',  _IFACE, 'set', 'type', 'monitor'], check=True, ...)
    subprocess.run(['ip',  'link', 'set',  _IFACE, 'up'],           check=True, ...)

def _set_managed_mode() -> None:
    subprocess.run(['ip',  'link', 'set',  _IFACE, 'down'], ...)
    subprocess.run(['iw',  'dev',  _IFACE, 'set', 'type', 'managed'], ...)
    subprocess.run(['ip',  'link', 'set',  _IFACE, 'up'], ...)
```

El uso de `subprocess` aquí es **solo para gestión del driver** (operaciones `iw`/`ip`),
nunca para parseo de paquetes — cumple la restricción técnica del proyecto.

---

## Arranque y dependencias

```python
if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit(1)   # requiere root para sockets RAW y gestión de interfaces

    hotspot_ip = os.popen("ip addr show wlan0 | awk '/inet /{print $2}' | cut -d/ -f1").read().strip()
    print(f'  Hotspot (móvil) → http://{hotspot_ip}:5000')

    app.run(host='0.0.0.0', port=5000, debug=False)
```

Al arrancar, la API imprime la IP del hotspot (`wlan0`) para confirmar que la red
está activa. Los scanners arrancan en reposo — la app móvil es la que lanza el escaneo.

---

# 4. Aplicación móvil Flutter

Aplicación Android desarrollada en Flutter/Dart. Se conecta a la API de la Pi por HTTP
y muestra los dispositivos detectados en un sonar animado.

---

## Arquitectura general

```
lib/main.dart  (fichero único, ~700 líneas)
│
├── DetectorApp           MaterialApp (tema oscuro, semilla verde)
│
├── Modelos de datos
│   ├── WifiDevice        Parseo JSON de /api/devices wifi[]
│   └── BtDevice          Parseo JSON de /api/devices bluetooth[]
│
├── Utilidades globales
│   ├── _zonas            Orden de zonas: cerca → dentro del aula → fuera
│   ├── _colorZona()      Color por zona (rojo / naranja / gris)
│   ├── _iconoZona()      Icono por zona
│   └── _formatTime()     Timestamp Unix → "HH:MM:SS"
│
├── HomePage              Pantalla principal
│   ├── Campo IP          Dirección de la Pi (por defecto 10.42.0.1)
│   ├── Botón Iniciar/Parar
│   ├── Barra de estado   Canal WiFi + contadores activos
│   └── SonarView         Vista del radar (visible solo cuando escanea)
│
├── SonarView             Radar animado
│   ├── AnimationController  Giro continuo cada 4 s
│   ├── SonarPainter      CustomPainter con el dibujo del radar
│   └── Burbujas          WifiBubble / BtBubble posicionadas sobre el canvas
│
├── Hojas de detalle (bottom sheets)
│   ├── WifiDetailSheet   Detalles completos de un dispositivo Wi-Fi
│   └── BtDetailSheet     Detalles completos de un dispositivo Bluetooth
│
└── HistoryScreen         Pantalla de historial al parar el escaneo
    ├── Estadísticas       Duración, totales Wi-Fi + BT
    ├── HistoryZoneSection  Sección por zona (cerca / dentro del aula / fuera)
    ├── WifiHistoryCard    Tarjeta de dispositivo Wi-Fi en historial
    └── BtHistoryCard      Tarjeta de dispositivo Bluetooth en historial
```

---

## Dependencias

```yaml
# pubspec.yaml
dependencies:
  flutter:
    sdk: flutter
  http: ^1.x     # peticiones HTTP a la API REST
```

Solo se añade el paquete `http`. Todo el resto (animaciones, pintura, JSON, layout)
usa el SDK estándar de Flutter.

---

## Comunicación con la API

### Configuración de red

El móvil se conecta a la red Wi-Fi "DetectorFraude" creada por la Pi (hotspot en `wlan0`).
La Pi siempre tiene la misma IP: `10.42.0.1`. La app usa esa IP por defecto y permite
cambiarla si se conecta desde otra red.

### Flujo de inicio

```
1. App abre → _syncStatus() via addPostFrameCallback
   GET /api/status → si scanning=true, la app entra en modo activo sin llamar /api/start
                   → si scanning=false, muestra pantalla vacía

2. Docente pulsa "Iniciar"
   POST /api/start → { ok: true }
   → Timer.periodic(3s) → GET /api/devices → setState con nuevos dispositivos

3. Docente pulsa "Parar"
   Timer cancela
   POST /api/stop
   GET /api/history → navegar a HistoryScreen
```

La sincronización al abrir (`_syncStatus`) evita el error "ya está escaneando" que
ocurría cuando la Pi llevaba tiempo activa y la app llamaba a `/api/start` de nuevo.

### Polling cada 3 segundos

```dart
_timer = Timer.periodic(const Duration(seconds: 3), (_) => _fetchDevices());

Future<void> _fetchDevices() async {
  final response = await http.get(Uri.parse('http://$_ip:5000/api/devices'));
  final data = jsonDecode(response.body);
  setState(() {
    _wifiDevices = (data['wifi'] as List).map((j) => WifiDevice.fromJson(j)).toList();
    _btDevices   = (data['bluetooth'] as List).map((j) => BtDevice.fromJson(j)).toList();
  });
}
```

---

## Sonar — SonarView y SonarPainter

### AnimationController

```dart
_controller = AnimationController(
  vsync: this,
  duration: const Duration(seconds: 4),
)..repeat();
```

El valor de la animación va de 0.0 a 1.0 cada 4 segundos. En cada frame,
`_controller.value * 2π` da el ángulo de barrido en radianes. El `CustomPainter`
se reconstruye en cada frame gracias a `AnimatedBuilder`.

### SonarPainter — elementos dibujados

1. **Fondo negro** — `canvas.drawCircle` con `clipPath` circular para recortar todo lo que salga fuera.
2. **Líneas de cuadrícula** — cuatro líneas diagonales cruzadas (eje X, eje Y, ±45°).
3. **Tres anillos de zona** con etiqueta:
   - `cerca` → radio 28% del radio total → color rojo
   - `dentro del aula` → radio 57% → color naranja
   - `fuera` → radio 82% → color gris
4. **Estela del barrido** — 8 arcos consecutivos de 5° cada uno con opacidad decreciente,
   dibujados como sectores circulares (`canvas.drawArc`) justo detrás de la línea de barrido.
5. **Línea de barrido** — línea verde desde el centro hasta el borde, en la posición actual.
6. **Punto central** — círculo verde pequeño en el origen.
7. **Borde exterior** — círculo verde con trazo fino.

### Posicionamiento determinista de dispositivos

Para evitar que las burbujas salten de posición cuando llegan nuevos dispositivos,
el ángulo de cada MAC es determinista:

```dart
double _angleForMac(String mac) {
  // Toma los últimos 8 dígitos hex de la MAC, los convierte a entero
  // y los mapea a [0, 2π]
  final hex = mac.replaceAll(':', '').substring(4);  // últimos 8 chars hex
  final value = int.parse(hex, radix: 16);
  return (value % 360) * (pi / 180);
}
```

El radio depende de la zona:

```dart
double _radiusForZone(String zone) => switch (zone) {
  'cerca'           => maxRadius * 0.28,
  'dentro del aula' => maxRadius * 0.57,
  _                 => maxRadius * 0.82,   // fuera
};
```

Cada burbuja se posiciona con `Positioned` calculando `(x, y)` a partir del ángulo
y el radio de su zona, centrado en el sonar.

### Burbuja de dispositivo

`WifiBubble` y `BtBubble` son círculos de 52×52 px con:
- Borde coloreado según zona (rojo / naranja / gris)
- Icono WiFi o Bluetooth
- Etiqueta corta del tipo de frame o dispositivo

Al tocar una burbuja se muestra un `showModalBottomSheet` con todos los detalles
del dispositivo: MAC, RSSI, zona, fabricante, timestamps, segundos desde última detección.

---

## Pantalla de historial

Al pulsar "Parar", la app llama a `GET /api/history` y navega a `HistoryScreen`.

La pantalla muestra:
- Estadísticas de sesión: duración, total Wi-Fi detectados, total BT detectados
- Dispositivos agrupados por zona (cerca → dentro del aula → fuera)
- Cada dispositivo en una tarjeta con sus datos completos
- Las zonas vacías (sin dispositivos) se ocultan automáticamente

---

# 5. Despliegue e integración del sistema

Esta sección documenta cómo preparar la Raspberry Pi para que el sistema funcione de
forma totalmente autónoma (sin intervención manual tras el arranque).

---

## Requisitos previos

- Raspberry Pi 5 con Raspberry Pi OS Bookworm 64-bit
- Adaptador Wi-Fi USB MT7612U conectado (aparece como `wlan1`)
- Python 3 + Flask instalado: `sudo pip3 install flask`
- Paquetes del sistema: `iw`, `NetworkManager` (incluidos en Raspberry Pi OS)

---

## Paso 1 — Configurar el hotspot (una sola vez)

El script `ap_setup.sh` crea la red Wi-Fi "DetectorFraude" en `wlan0` (el Wi-Fi integrado
de la Pi) y marca `wlan1` como no gestionada por NetworkManager para que el scanner
pueda controlarla libremente.

```bash
sudo ./ap_setup.sh
```

Internamente usa `nmcli` para crear una conexión de tipo hotspot:

```bash
nmcli device wifi hotspot \
    ifname wlan0 \
    ssid DetectorFraude \
    password "detector1234" \
    con-name DetectorFraude-AP

# Marcar wlan1 como unmanaged para que NetworkManager no interfiera
nmcli device set wlan1 managed no
```

El hotspot se configura con `autoconnect yes`, de modo que arranca automáticamente
en cada reinicio sin ningún comando adicional.

**IP fija del hotspot:** `10.42.0.1`  
**Red asignada a los clientes:** `10.42.0.0/24`

Este paso solo hay que ejecutarlo una vez. Si hay que reinstalar la Pi desde cero,
ejecutarlo de nuevo.

---

## Paso 2 — Instalar el servicio systemd (una sola vez)

El script `service_setup.sh` instala `detector-fraude.service` como servicio systemd
para que la API REST arranque automáticamente con la Pi.

```bash
sudo ./service_setup.sh
```

Internamente:
```bash
cp detector-fraude.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable detector-fraude    # arranque automático en boot
systemctl restart detector-fraude   # arranque inmediato
```

Al finalizar muestra el estado del servicio para confirmar que está activo.

---

## Unidad systemd — `detector-fraude.service`

```ini
[Unit]
Description=Detector Fraude Académico — API REST
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/raspi831/TFG-Detector
ExecStart=/usr/bin/python3 /home/raspi831/TFG-Detector/web/api.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Puntos clave:
- `After=network-online.target NetworkManager.service` — garantiza que el hotspot
  ya está activo antes de lanzar la API (la IP `10.42.0.1` ya existe en `wlan0`).
- `User=root` — necesario para abrir sockets RAW (AF_BLUETOOTH, AF_PACKET) y para
  ejecutar `iw`/`ip` sin sudo.
- `Restart=on-failure` con `RestartSec=5` — si la API cae por cualquier motivo,
  el sistema la relanza automáticamente tras 5 segundos.
- Los logs van al journal del sistema y se pueden consultar con:
  ```bash
  sudo journalctl -u detector-fraude -f
  ```

---

## Comandos de mantenimiento

```bash
# Ver estado del servicio
sudo systemctl status detector-fraude

# Reiniciar tras cambios en el código Python
sudo systemctl restart detector-fraude

# Ver logs en tiempo real
sudo journalctl -u detector-fraude -f

# Parar el servicio manualmente
sudo systemctl stop detector-fraude

# Cambiar modo wlan1 manualmente (para depuración)
sudo ./wlan1.sh monitor    # pone wlan1 en modo monitor
sudo ./wlan1.sh managed    # restaura modo managed
```

---

## Flujo completo de uso

```
Pi arranca
  ├─ NetworkManager arranca el hotspot "DetectorFraude" en wlan0 (10.42.0.1)
  └─ systemd arranca detector-fraude.service → API disponible en :5000

Docente conecta el móvil a la red "DetectorFraude"
  └─ Abre la app Flutter

App abre
  └─ GET /api/status → sincroniza estado con la Pi

Docente pulsa "Iniciar"
  ├─ POST /api/start → wlan1 pasa a modo monitor, BluetoothScanner + WifiScanner arrancan
  └─ App: Timer cada 3 s → GET /api/devices → sonar actualizado en tiempo real

Examen transcurre
  └─ Dispositivos aparecen como burbujas en el sonar, posicionados por zona de señal

Docente pulsa "Parar"
  ├─ POST /api/stop → scanners se detienen, wlan1 vuelve a modo managed
  ├─ GET /api/history → historial completo de la sesión
  └─ App: navega a HistoryScreen con todos los dispositivos agrupados por zona
```

---

## Archivos del proyecto

| Archivo | Función | ¿Es imprescindible? |
|---------|---------|---------------------|
| `scanner/bluetooth.py` | BluetoothScanner HCI RAW | Sí |
| `scanner/wifi_capture.py` | WifiScanner AF_PACKET | Sí |
| `scanner/__init__.py` | Hace `scanner` importable | Sí |
| `web/api.py` | API REST Flask | Sí |
| `web/__init__.py` | Hace `web` importable | Sí |
| `detector-fraude.service` | Unidad systemd | Sí |
| `ap_setup.sh` | Configura hotspot wlan0 | Primera instalación |
| `service_setup.sh` | Instala servicio systemd | Primera instalación |
| `wlan1.sh` | Cambio manual de modo wlan1 | Depuración |
| `main.py` | Interfaz de consola (versión antigua) | No |
| `core/__init__.py` | Carpeta vacía sin uso | No |
| `diag_radiotap.py` | Diagnóstico RadioTap | No |
| `scanner/DESARROLLO.md` | Este documento | No (documentación) |