#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys

MCAST_GRP = '224.0.0.0'
MCAST_PORT = 30003

def main():
    # Crear socket UDP para multicast
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Permitir reuso de la dirección (para no bloquear si se reinicia rápido)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)


    # Asociar (bind) el socket al puerto multicast (en cualquier interfaz local)
    sock.bind(('', MCAST_PORT))

    # Suscribirnos al grupo multicast 224.0.0.0 en la interfaz "por defecto"
    group_bin = socket.inet_aton(MCAST_GRP)
    mreq = struct.pack('4sL', group_bin, socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"Escuchando mensajes multicast en {MCAST_GRP}:{MCAST_PORT}...")
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            print(f"[RECIBIDO] Desde {addr}: {data.decode('utf-8', errors='replace')}")
    except KeyboardInterrupt:
        print("\nCerrando receptor multicast.")
    finally:
        sock.close()

if __name__ == '__main__':
    main()
