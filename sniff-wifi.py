from datetime import datetime
import os
import time
import threading
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11ProbeReq
from manuf import manuf


INTERFAZ = "wlp4s0"
UMBRAL_PROXIMIDAD = -90
CANALES_PRIORITARIOS = [1, 6, 9]
mac_parser = manuf.MacParser(update=False)

dispositivos_vistos = {}

def saltos_canal():
    while True:
        for canal in range (1, 14):
            os.system(f"iwconfig {INTERFAZ} channel {canal}")
            if canal in CANALES_PRIORITARIOS:
                time.sleep(0.6)
            else:
                time.sleep(0.2)

def obtener_fabricante(mac): #Obtener fabricante mediante la dirección mac
    fabricante = mac_parser.get_manuf(mac)
    return fabricante if fabricante else "Desconocido"

def procesar_paquete(pkt):
    if pkt.haslayer(Dot11):

        es_busqueda = False
        es_datos = False
        ssid = "?"

        #Type == 0 -> Encontrar redes(Management)
        #Type == 1 -> Control(ACK)
        #Type == 2 -> Datos
        #Subtipos de Gestión == 0
        #Subtypes == 4 -> Probe Request -> Busqueda de red conocida
        #Subtypes == 5 -> Probe Response -> Respuesta del router
        #Subtypes == 8 -> Beacon -> Anuncio del router
        #Subtypes == 11 -> Autenticacion
        #Subtypes == 12 -> Cortar conexión
        #Subtipos de Datos == 2
        #Subtypes == 0 -> Trama de datos
        #Subtypes == 8 -> Prioriza voz o video.
        if pkt.type == 0 and pkt.subtype == 4:
            es_busqueda = True
        elif pkt.type == 2:
            es_datos = True

        if es_datos or es_busqueda:
            mac = pkt.addr2 #Almaceno direcciones mac
            if es_busqueda:
                ssid = pkt.info.decode('utf-8', errors='ignore')
                if ssid == False:
                    ssid = "?"
            try:
                rssi = pkt.dBm_AntSignal #Almaceno potencia
            except AttributeError:
                rssi = None

            if mac and rssi is not None:
                if rssi > UMBRAL_PROXIMIDAD:
                    tipo_msg = "Buscando red" if es_busqueda else "Enviando datos"
                    if mac not in dispositivos_vistos or (abs(dispositivos_vistos[mac]['rssi'] - rssi) > 10 and dispositivos_vistos[mac]['rssi'] < rssi):
                        fabricante = obtener_fabricante(mac)
                        dispositivos_vistos[mac] = {
                            "mac": mac,
                            "rssi": rssi,
                            "tipo": tipo_msg,
                            "ssid": ssid,
                            "fabricante": fabricante
                        }
                        print(f"Dispositivo detectado con MAC: {mac} | Tipo: {tipo_msg} | Potencia: {rssi} dBm | Canal: {pkt.channel if hasattr(pkt, 'channel') else '?'}")

def imprimir_resumen():
    print("\n\n" + "="*50)
    print("Dispositivos detectados.")
    print("="*50)
    print(f"{'FABRICANTE':<20} | {'DIRECCIÓN MAC':<20} | {'POTENCIA MÁXIMA':<15} | {'ESTADO'}")
    print("-"*50)
    
    sorted_devs = sorted(dispositivos_vistos.items(), key=lambda x: x[1]['rssi'], reverse=True)
    
    for mac, datos in sorted_devs:
        potencia = datos['rssi']
        tipo = datos['tipo']
        ssid = datos['ssid']
        fabricante = datos['fabricante']
            
        print(f"{mac:<20} | {fabricante[:20]:<20} | {potencia:>12} dBm | Tipo: {tipo} | Ssid: {ssid}")
    print("="*50)

def iniciar_escaneo():
    print(f"--- Iniciando Herramienta de Detección de Fraude ---")
    print(f"Escaneando en interfaz: {INTERFAZ}")
    print(f"Umbral de alerta: > {UMBRAL_PROXIMIDAD} dBm")
    print("-" * 50)

    hilo_canales = threading.Thread(target=saltos_canal, daemon=True)
    hilo_canales.start()

    try:
        sniff(iface=INTERFAZ, prn=procesar_paquete, store=0)
    except KeyboardInterrupt:
        print("\nDeteniendo el escaneo...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    iniciar_escaneo()
    imprimir_resumen()