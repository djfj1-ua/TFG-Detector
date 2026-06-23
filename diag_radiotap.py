#!/usr/bin/env python3
"""
Diagnóstico RadioTap — captura 10 frames de wlan1 y muestra
la estructura de sus cabeceras RadioTap (palabras present, campos activos).
Ejecutar: sudo python3 diag_radiotap.py
"""
import socket
import struct
import sys

IFACE   = 'wlan1'
SAMPLES = 10

FIELD_NAMES = {
    0: 'TSFT', 1: 'Flags', 2: 'Rate', 3: 'Channel', 4: 'FHSS',
    5: 'dBm_Sig', 6: 'dBm_Noise', 7: 'LockQuality', 8: 'TXAtten',
    9: 'dBTXAtten', 10: 'dBmTXPower', 11: 'Antenna',
    12: 'dB_Sig', 13: 'dB_Noise', 14: 'RXFlags', 15: 'TXFlags',
    16: 'RTSRetries', 17: 'DataRetries',
}

def active_bits(word, offset=0):
    return [offset + i for i in range(31) if word & (1 << i)]

def parse_header(raw):
    if len(raw) < 8:
        return
    header_len = struct.unpack_from('<H', raw, 2)[0]
    words, off = [], 4
    while True:
        if off + 4 > len(raw):
            break
        w = struct.unpack_from('<I', raw, off)[0]
        words.append(w)
        off += 4
        if not (w & (1 << 31)):
            break

    bits = []
    for idx, w in enumerate(words):
        bits += active_bits(w, idx * 32)

    named = [FIELD_NAMES.get(b, f'bit{b}') for b in bits if b not in (31, 63)]

    print(f'  header_len={header_len}  present_words={len(words)}  '
          f'words={[f"0x{w:08X}" for w in words]}')
    print(f'  campos presentes: {named}')
    print(f'  raw header: {raw[:header_len].hex()}')
    print()

if __name__ == '__main__':
    if __import__('os').geteuid() != 0:
        print('Ejecutar como root: sudo python3 diag_radiotap.py')
        sys.exit(1)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((IFACE, 0))
    sock.settimeout(5.0)

    print(f'Capturando {SAMPLES} frames de {IFACE}...\n')
    seen = 0
    while seen < SAMPLES:
        try:
            raw = sock.recv(4096)
        except socket.timeout:
            print('Timeout — ¿está wlan1 en modo monitor?')
            break
        print(f'Frame {seen + 1}:')
        parse_header(raw)
        seen += 1

    sock.close()