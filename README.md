# 📡 Detector de Fraude Académico vía Wi-Fi (TFG)

Este proyecto tiene como objetivo evaluar las tecnologías empleadas actualmente para el fraude en pruebas académicas y el desarrollo de una herramienta capaz de detectar dispositivos sospechosos mediante el análisis del tráfico de la red.

---

## 🛠️ Requisitos Previos

Para el correcto funcionamiento del sistema, se requiere:

* **Hardware:** Tarjeta de red Wi-Fi compatible con **Modo Monitor** (ej: Chipsets Atheros o RT3070).
* **Sistema Operativo:** Distribuciones basadas en Linux (Ubuntu, Kali Linux, Raspberry Pi OS).
* **Software:** Python 3.x y la suite de herramientas `aircrack-ng`.

---

## 📦 Instalación

Clona el repositorio y configura el entorno de dependencias:

```bash
# Clonar el proyecto
git clone [https://github.com/djfj1-ua/TFG-Detector.git](https://github.com/djfj1-ua/TFG-Detector.git)
cd TFG-Detector

# Instalar librerías de Python necesarias
sudo pip install -r requirements.txt

# Instalar herramientas de red (aircrack-ng)
sudo apt update && sudo apt install aircrack-ng -y
```

## 📖 Guía de Uso

Sigue estos pasos en orden para poner en marcha el sistema de detección.

### 1. Identificar la interfaz de red
Busca el nombre de tu interfaz de red (ej. `wlp4s0`, `wlan0`):
```bash
ifconfig
```
### 2. Pon la tarjeta en modo monitor.
```bash
# Uso: sudo ./wifi_mode.sh monitor <Interfaz>
sudo ./wifi_mode.sh monitor wlp4s0
```

### 3. Ejecuta el programa de detección de dispositivos.
```bash
# Uso: sudo python3 sniff-wifi.py <Interfaz_Monitor>
sudo python3 sniff-wifi.py wlp4s0mon
```
