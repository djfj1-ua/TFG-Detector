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
