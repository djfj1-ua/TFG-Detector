# 📡 Detector Dispositivos - TFG

Este TFG tiene como objetivo evaluar las tecnologías empleadas actualmente para el fraude en la realización de pruebas académicas y el desarrollo de una herramienta tecnológica que permita detectar el uso de las mismas.

# Modo de Empleo
## Requisitos Previos
* **Hardware:** Tarjeta de red Wi-Fi con soporte para **Modo Monitor**.
* **Sistema:** Linux (Ubuntu, Kali, Raspberry Pi OS).
* **Dependencias:** Python 3.x y las herramientas de `aircrack-ng`.

## Instalación
```bash
git clone https://github.com/djfj1-ua/TFG-Detector.git
cd TFG-Detector
sudo pip install -r requerimientos.txt

# Instalar herramientas de red
sudo apt update && sudo apt install aircrack-ng -y
