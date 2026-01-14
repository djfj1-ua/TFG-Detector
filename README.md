# TFG-Detector
Este TFG tiene como objetivo evaluar las tecnologías empleadas actualmente para el fraude en la realización de pruebas académicas y el desarrollo de una herramienta tecnológica que permita detectar el uso de las mismas.

# 📡 WiFi Fraud Detector - TFG

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Sistema de detección de dispositivos sospechosos en entornos académicos mediante el análisis de tramas 802.11 y triangulación por RSSI.

## 🛠️ Características
- **Análisis de Capa 2:** Captura de *Probe Requests* y *Data Frames*.
- **Identificación OUI:** Resolución de fabricantes en tiempo real (Apple, Samsung, Espressif...).
- **Filtro de Proximidad:** Clasificación de riesgo basada en la potencia de señal (dBm).
- **Modo Monitor:** Automatización del salto de canales (Channel Hopping).

## 🚀 Instalación
```bash
git clone [https://github.com/djfj1-ua/TFG-Detector.git](https://github.com/djfj1-ua/TFG-Detector.git)
cd TFG-Detector
sudo pip install -r requerimientos.txt
