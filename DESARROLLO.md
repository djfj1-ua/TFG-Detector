# TFG — Herramienta de detección de fraude en pruebas académicas
## Diario de desarrollo

---

## Índice

1. [Descripción del proyecto](#1-descripción-del-proyecto)
2. [Hardware utilizado](#2-hardware-utilizado)
3. [Módulo: Scanner Bluetooth](#3-módulo-scanner-bluetooth)
   - [Arquitectura](#31-arquitectura)
   - [BLE — raw HCI socket](#32-ble--raw-hci-socket)
   - [Bluetooth Clásico — HCI Inquiry](#33-bluetooth-clásico--hci-inquiry)
   - [Problemas encontrados y soluciones](#34-problemas-encontrados-y-soluciones)
4. [Pendiente](#4-pendiente)

---

## 1. Descripción del proyecto

El objetivo del TFG es detectar tecnologías empleadas habitualmente para el fraude
en pruebas de evaluación académicas (pinganillos, auriculares inalámbricos, smartphones,
smartwatches) y desarrollar una herramienta que permita identificar su presencia en el
aula durante un examen.

La herramienta se ejecuta sobre una **Raspberry Pi 5** y utiliza sus interfaces de
radio nativas (WiFi y Bluetooth) para escanear el espectro sin librerías de terceros
para el procesado de paquetes — todo el parseo se realiza sobre sockets raw de Python.

---

## 2. Hardware utilizado

| Componente | Modelo | Notas |
|---|---|---|
| SBC | Raspberry Pi 5 Model B Rev 1.0 | ARM64, kernel 6.12.75+rpt-rpi-2712 |
| Bluetooth | BCM (UART, hci0) | Integrado en la Pi 5 |
| WiFi monitor | MediaTek MT7610 (wlan1) | Adaptador USB externo, soporta modo monitor |
| WiFi sistema | Broadcom (wlan0) | Integrado, usado para conectividad de red |

---

## 3. Módulo: Scanner Bluetooth

**Fichero:** `scanner/bluetooth.py`

El scanner detecta dos tipos de dispositivos Bluetooth:

- **BLE (Bluetooth Low Energy):** smartphones, smartwatches, auriculares TWS, beacons.
  Se detectan aunque no estén emparejados con ningún dispositivo, ya que emiten
  *advertising packets* de forma continua.
- **Bluetooth Clásico (BR/EDR):** teléfonos en modo visible, auriculares tradicionales
  en modo pairing. Se detectan mediante el procedimiento de *Inquiry*.

### 3.1 Arquitectura

```
BluetoothScanner
├── _ble_loop()          hilo principal — abre socket HCI, activa BLE scan e Inquiry
│   └── _handle_hci_event()   procesa cada paquete HCI recibido
│       ├── BLE events (0x3E) → _register_ble_device()
│       ├── Inquiry RSSI (0x22) → _register_classic_device()
│       ├── Extended Inquiry (0x2F) → _register_classic_device()
│       └── Inquiry Complete (0x01) → espera 15s y relanza Inquiry
└── _dispatch_loop()     hilo secundario — entrega BTDevice al callback on_device

BTDevice (dataclass)
├── mac, name, rssi, bt_type ('BLE'|'CLASSIC')
├── addr_type ('public'|'random'), adv_type, manufacturer_id, uuids
└── first_seen, last_seen  (timestamps float)
```

### 3.2 BLE — raw HCI socket

Se abre un socket `AF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` sobre `hci0` y se
interactúa directamente con el controlador mediante comandos HCI binarios.

#### Comandos enviados

```
LE_Set_Scan_Parameters (OGF=0x08, OCF=0x000B)
  Scan_Type=0x01 (activo), Interval=0x0200, Window=0x0200
  Own_Address=public, Filter=aceptar_todo

LE_Set_Scan_Enable (OGF=0x08, OCF=0x000C)
  Enable=0x01, Filter_Duplicates=0x00
```

La ventana de escaneo de 320 ms (0x0200 × 0.625 ms) con duty cycle 100%
es necesaria para capturar dispositivos que anuncian con poca frecuencia
(smartphones con pantalla apagada, modo ahorro de batería).

#### Filtro HCI — problema crítico resuelto

El kernel Linux expone el filtro del socket HCI mediante `setsockopt(SOL_HCI, HCI_FILTER)`.
El struct del kernel es:

```c
struct hci_filter {
    unsigned long type_mask;    // 8 bytes en ARM64
    unsigned long event_mask[2]; // 16 bytes en ARM64
    uint16_t opcode;            // 2 bytes
};  // total: 26 bytes + 6 padding = 32 bytes
```

**Problema:** la documentación de BlueZ asume `uint32_t` (struct de 14 bytes),
pero en kernels 64-bit `unsigned long` ocupa 8 bytes → struct de 32 bytes.
Pasar 14 bytes provoca `EINVAL`.

**Segundo problema:** el bit de cada evento en `event_mask` no sigue la
indexación estándar de la spec. Verificado empíricamente en el kernel 6.12
de la Raspberry Pi 5: el bit para el evento con código `N` es `N & 31`
dentro de `event_mask[0]`, independientemente del valor de N.
Los bits de `event_mask[1]` no son efectivos en este kernel.

```python
# Implementación correcta para este kernel
class _KernelHciFilter(ctypes.Structure):
    _fields_ = [
        ('type_mask',  ctypes.c_ulong),
        ('event_mask', ctypes.c_ulong * 2),
        ('opcode',     ctypes.c_uint16),
    ]

def build_hci_filter(ptype, *events):
    f = _KernelHciFilter()
    f.type_mask = 1 << ptype
    for event in events:
        f.event_mask[0] |= 1 << (event & 31)  # siempre event_mask[0]
    return bytes(f)
```

#### Parseo de LE Advertising Report (evento 0x3E, subevent 0x02)

```
[0]   HCI packet type (0x04 = event)
[1]   Event code (0x3E = LE Meta)
[2]   Parameter total length
[3]   Subevent code (0x02 = Advertising Report)
[4]   Num_Reports
Para cada report:
  [+0] Event_Type (1B)
  [+1] Address_Type (1B)  — 0x00=public, 0x01=random
  [+2] Address (6B, little-endian)
  [+8] Data_Length (1B)
  [+9] Data (Data_Length B)  — AD structures TLV
  [+9+Data_Length] RSSI (1B, signed)
```

Los **AD structures** tienen formato TLV: `[length][type][value...]`.
Se parsean los tipos relevantes para la detección:
- `0x08` / `0x09`: nombre del dispositivo
- `0xFF`: datos del fabricante (2B Manufacturer ID + payload)
- `0x02`-`0x07`: UUIDs de servicio

### 3.3 Bluetooth Clásico — HCI Inquiry

El procedimiento de Inquiry permite descubrir dispositivos Bluetooth Clásico
que estén en **modo visible (discoverable)**. Se usa el LAP GIAC
(`0x9E8B33`) que descubre todos los dispositivos visibles.

```
HCI_Inquiry (OGF=0x01, OCF=0x0001)
  LAP=0x9E8B33, Inquiry_Length=8 (→ 8×1.28s ≈ 10s), Num_Responses=0
```

Se procesan dos tipos de respuesta:

**Evento 0x22 — Inquiry Result with RSSI** (respuesta básica):
```
Num_Responses (1B)
Por respuesta (15B):
  BD_ADDR (6B) | Page_Scan_Mode (1B) | Reserved (2B)
  Class_of_Device (3B) | Clock_Offset (2B) | RSSI (1B signed)
```

**Evento 0x2F — Extended Inquiry Result** (respuesta con nombre):
```
Num_Responses=1 (1B)
BD_ADDR (6B) | PSR (1B) | Reserved (1B)
Class_of_Device (3B) | Clock_Offset (2B) | RSSI (1B signed)
EIR (240B) — mismo formato TLV que los AD structures de BLE
```

### 3.4 Problemas encontrados y soluciones

#### Interferencia de radio entre Inquiry y BLE

**Problema:** el chip BCM de la Pi 5 tiene un único transceptor de radio
compartido entre BLE y Bluetooth Clásico. Al ejecutar el Inquiry de forma
continua (relanzándolo inmediatamente al completar), el chip dedica el radio
casi exclusivamente a saltar entre las 79 frecuencias del Inquiry clásico,
impidiendo que el BLE scan reciba advertising packets con regularidad.
El efecto observado: el RSSI de los dispositivos BLE deja de actualizarse
y queda congelado en el último valor recibido.

**Solución:** esperar 15 segundos tras cada Inquiry Complete antes de
relanzar el siguiente. Durante esa pausa, el hardware BLE tiene el radio
libre y procesa los advertising packets acumulados en el buffer del kernel.
El ciclo resultante es: ~10s de Inquiry → 15s de BLE limpio → repite.

```python
elif event_code == HCI_EV_INQUIRY_COMPLETE:
    time.sleep(15)   # BLE limpio antes del siguiente Inquiry
    self._send_hci_cmd(sock, OGF_LINK_CTL, OCF_INQUIRY, ...)
```

#### Dispositivos Classic BT que no aparecen

**Causa:** el Inquiry solo detecta dispositivos en **modo discoverable**
(visible). Los smartphones no están en modo discoverable por defecto;
solo lo activan cuando el usuario abre los ajustes de Bluetooth o durante
el proceso de emparejamiento. Un auricular ya emparejado con un teléfono
no es discoverable a menos que se ponga en modo pairing.

**Implicación para el TFG:** un alumno que ya tenga el auricular conectado
al móvil antes del examen no será detectado por el Inquiry. Sin embargo,
el auricular BLE sí emite advertising packets y se detecta por ese canal.
Los pinganillos analógicos (RF/UHF) requieren el scanner SDR.

#### Duplicados de comando Inquiry

**Problema:** al usar `socket.timeout` para detectar cuándo relanzar el Inquiry,
si `next_inquiry` no se actualiza inmediatamente al enviar el comando,
cada timeout (cada 2s) envía un Inquiry nuevo mientras el anterior está
activo. El controlador rechaza los duplicados con `Command Disallowed (0x05)`
y puede quedar en estado inconsistente.

**Solución:** actualizar `next_inquiry = float('inf')` inmediatamente tras
el envío, y restaurarlo solo al recibir `INQUIRY_COMPLETE`.

---

## 4. Pendiente

| Módulo | Descripción |
|---|---|
| `scanner/wifi.py` | Raw 802.11 en monitor mode, parseo RadioTap + frames de gestión |
| `scanner/oui.py` | Lookup de fabricante por prefijo MAC (base de datos IEEE OUI) |
| `core/models.py` | Dataclasses unificados Device, Alert, ExamSession |
| `core/db.py` | Persistencia SQLite — historial de dispositivos y alertas |
| `core/detector.py` | Motor de alertas: whitelist, umbral de RSSI, dispositivos sospechosos |
| `web/server.py` | Dashboard HTTP con Server-Sent Events para actualizaciones en tiempo real |
| `main.py` | Punto de entrada: orquesta scanners, detector y dashboard |
