#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import sys
import signal
import time

# Puerto fijo para ambas partes
PORT = 30000

# Creamos una variable global para el socket del servidor
server_socket = None

def signal_handler(sig, frame):
    """
    Manejador de señales para Ctrl + C (SIGINT) o SIGTERM.
    Cierra el socket del servidor y sale.
    """
    print("\n[SALIR] Cerrando socket y saliendo...")
    if server_socket:
        try:
            server_socket.close()
        except Exception as e:
            print("[ERROR al cerrar socket]:", e)
    sys.exit(0)

# Registramos el manejador de señal para Ctrl + C
signal.signal(signal.SIGINT, signal_handler)
# Opcionalmente, para SIGTERM también:
signal.signal(signal.SIGTERM, signal_handler)

def server_thread(local_ip, local_port):
    """
    Hilo que se encarga de escuchar permanentemente conexiones entrantes
    en (local_ip:port), recibir mensajes y mostrarlos en pantalla.
    """
    global server_socket
    # Crear socket TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Reutilizar dirección (evita errores si re-ejecutas rápido)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Asociar a IP y puerto
    server_socket.bind((local_ip, local_port))
    # Escuchar con backlog = 5
    server_socket.listen(5)

    print(f"[SERVIDOR] Escuchando en {local_ip}:{local_port}")

    while True:
        try:
            conn, addr = server_socket.accept()
            # Recibir datos (máx 1024 bytes)
            data = conn.recv(1024)
            if data:
                mensaje = data.decode('utf-8')
                print(f"\n[RECIBIDO de {addr[0]}:{addr[1]}] {mensaje}")
            conn.close()
        except Exception as e:
            print(f"[SERVIDOR] Error: {e}")
            break

def send_message(remote_ip, remote_port, mensaje):
    """
    Envía un mensaje (TCP) a la dirección remota (remote_ip:port).
    """
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((remote_ip, remote_port))
        client_sock.sendall(mensaje.encode('utf-8'))
        client_sock.close()
    except Exception as e:
        print(f"[CLIENTE] Error al enviar mensaje a {remote_ip}:{remote_port} -> {e}")

def main():
    # Pedimos datos de configuración por consola
    local_ip = sys.argv[1]  # "0.0.0.0" para escuchar en todas las interfaces locales
    #local_port = int(input("¿En qué puerto quieres escuchar? (p.ej. 30000): ").strip())

    #remote_ip = input("IP remota del otro nodo (p.ej. 192.168.1.10): ").strip()
    #remote_port = int(input("Puerto remoto (p.ej. 30000): ").strip())

    local_port = int(sys.argv[2])
    remote_ip = sys.argv[3]
    remote_port = int(sys.argv[4])

    # Lanzamos el servidor en un hilo aparte para no bloquear el envío
    hilo_servidor = threading.Thread(
        target=server_thread,
        args=(local_ip, local_port),
        daemon=True
    )
    hilo_servidor.start()

    print("\n¡Listo! Puedes empezar a chatear. Escribe tu mensaje y presiona Enter.")
    print("Usa Ctrl + C para salir.\n")

    # Bucle principal: leer mensajes de la consola y enviarlos
    
    time.sleep(1)
    while True:
        try:
            mensaje = input("Tú: ")
            if mensaje.strip():
                send_message(remote_ip, remote_port, mensaje)
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n[SALIENDO] Deteniendo el chat...")
            if server_socket:
                server_socket.close()
                sys.exit(0)

if __name__ == "__main__":
    main()
