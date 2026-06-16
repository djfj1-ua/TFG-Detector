# DESARROLLO — bluetoothPrueba.py

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
        # rssi >= -85 → 'dentro'
        # rssi >= -95 → 'cerca'
        # rssi <  -95 → 'fuera'
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

### Implementación

El filtro se aplica en `main()` al obtener la lista para mostrar:

```python
ahora = time.time()
devs  = [
    d for d in scanner.devices
    if (d.name or d.manufacturer_id is not None or d.uuids)
    and (ahora - d.last_seen) <= 20
]
```

El caché interno (`_seen`) no se modifica: todos los dispositivos siguen
almacenados y actualizando su `last_seen` y `rssi` aunque no sean visibles.

---

## Debug integrado

El scanner en su versión actual escribe un log detallado en `/tmp/bt_debug.log`
con timestamp relativo al arranque. Útil para analizar el comportamiento del
firmware.

```bash
# En otra terminal mientras corre el scanner:
tail -f /tmp/bt_debug.log

# Buscar eventos concretos:
grep "INQUIRY_COMPLETE\|INQUIRY_RESULT\|EXTENDED" /tmp/bt_debug.log
grep "EVENT  code=" /tmp/bt_debug.log | sort | uniq -c
```

La pantalla muestra en tiempo real:
- Estado del hilo de captura (VIVO / MUERTO)
- Contadores: eventos totales, BLE adv, Inq results, Inq complete, OSErrors
- Tiempo desde el último evento recibido y su código
- Edad de cada dispositivo en segundos (`[Xs]`)

---

## Ejecución

```bash
sudo python3 bluetoothPrueba.py
```

Requiere root para abrir sockets HCI RAW. Para con Ctrl+C y muestra el resumen
final de dispositivos detectados.

---

## Archivos relacionados

| Archivo | Descripción |
|---------|-------------|
| `bluetoothPrueba.py` | Scanner activo, versión con debug completo |
| `bluetooth.py` | Versión anterior con doble socket (BLE + Inquiry separados). Sirve como referencia de arquitectura alternativa que sí recibe `INQUIRY_COMPLETE` |

---

---

# Módulo Wi-Fi — `wifi_capture.py`

Scanner 802.11 en modo monitor para detección de dispositivos inalámbricos durante exámenes.  
Hardware: Raspberry Pi 5 · Alfa AWUS036ACHM (MT7612U) en `wlan1` · modo monitor

> **Restricción legal (igual que Bluetooth):** Solo captura pasiva. No se inyectan frames,
> no se interfiere con ninguna señal. La interfaz solo escucha.

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

La interfaz `wlan1` debe estar en modo monitor antes de ejecutar el script.
El script no cambia el modo por sí solo (requeriría también bajar/subir la interfaz):

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
_CHANNELS_5GHZ = [
    36, 40, 44, 48,              # UNII-1  (sin DFS, preferidos)
    52, 56, 60, 64,              # UNII-2  (DFS — el driver puede rechazarlos)
    100, 104, 108, 112, 116,     # UNII-2E (DFS)
    132, 136, 140,
    149, 153, 157, 161, 165,     # UNII-3
]
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
        # rssi >= -85 dBm → 'dentro'   (dentro del aula)
        # rssi >= -95 dBm → 'cerca'    (pasillo o adyacente)
        # rssi <  -95 dBm → 'fuera'    (lejos del perímetro)
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

## Modelo de proximidad

Igual que en Bluetooth, se usan tres zonas calibradas para aula estándar:

| Zona | RSSI | Significado |
|------|------|-------------|
| `dentro` | ≥ -85 dBm | El dispositivo está dentro del aula |
| `cerca` | ≥ -95 dBm | Pasillo inmediato o aula adyacente |
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

- **`hop_interval`**: reducirlo (ej. 0.10 s) mejora la cobertura temporal pero puede
  perder frames cortos como ACKs. 0.20 s es el equilibrio razonable para Probe Requests
  (que se retransmiten varias veces).
- **`scan_5ghz`**: activarlo sube el ciclo de 13 a 34 canales (barrido completo ≈ 6.8 s).
  Útil si se sospecha del uso de adaptadores 5 GHz (cámaras espía, dongles modernos).

---

## Ejecución

```bash
# 1. Poner wlan1 en modo monitor
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up

# 2. Ejecutar el scanner
sudo python3 scanner/wifi_capture.py
```

Requiere root para abrir el socket `AF_PACKET RAW`. Para con Ctrl+C e imprime
el resumen final de todos los dispositivos detectados durante la sesión.

---

## Archivos relacionados (Wi-Fi)

| Archivo | Descripción |
|---------|-------------|
| `scanner/wifi_capture.py` | Scanner Wi-Fi 802.11 en modo monitor con channel hopping |
| `scanner/bluetooth.py` | Scanner Bluetooth BLE + Clásico (HCI RAW) |
| `scanner/DESARROLLO.md` | Este documento |
