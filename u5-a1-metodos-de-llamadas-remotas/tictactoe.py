#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import sys
import signal
import time
import re

# Creamos una variable global para el socket del servidor
server_socket = None
player = None
oponent = None
ganador = None
turno = "X"
tictactoe = [[' ',' ',' '],[' ',' ',' '],[' ',' ',' ']]

def check_winner():
    for row in range(3):
        if tictactoe[row][0] == tictactoe[row][1] == tictactoe[row][2] and tictactoe[row][0] != '-':
            return tictactoe[row][0]
    for col in range(3):
        if tictactoe[0][col] == tictactoe[1][col] == tictactoe[2][col] and tictactoe[0][col] != '-':
            return tictactoe[0][col]
    if tictactoe[0][0] == tictactoe[1][1] == tictactoe[2][2] and tictactoe[0][0] != '-':
        return tictactoe[0][0]
    if tictactoe[0][2] == tictactoe[1][1] == tictactoe[2][0] and tictactoe[0][2] != '-':
        return tictactoe[0][2]
    return None

def print_board():
    print("================")
    print(f"  [Player '{player}']\n Tablero actual:\n")
    for row in range(3):
        print(f"    ", end="")
        for col in range(3):
            print(f"{tictactoe[row][col]}", end=" ")
        print("")
    print("================")

def make_move(message, jugador):
    pattern = re.compile(r'^[123],[123]$')
    message = message.strip()
    valid = bool(pattern.match(message))
    if not valid:
        return False

    coordenadas = message.split(",")
    row = int(coordenadas[0])-1
    col = int(coordenadas[1])-1

    if tictactoe[row][col] == '-':
        tictactoe[row][col] = jugador
        return True
    else:
        return False

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
    global oponent
    global turno, ganador
    # Crear socket TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Reutilizar dirección (evita errores si re-ejecutas rápido)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Asociar a IP y puerto
    server_socket.bind((local_ip, local_port))
    # Escuchar con backlog = 5
    server_socket.listen(5)

    print(f"[SERVIDOR] Escuchando en {local_ip}:{local_port}")

    while ganador is None:
        try:
            conn, addr = server_socket.accept()
            # Recibir datos (máx 1024 bytes)
            data = conn.recv(1024)
            if data:
                mensaje = data.decode('utf-8')
                #print(f"\n[RECIBIDO de {addr[0]}:{addr[1]}] {mensaje}")
                valid = make_move(mensaje, oponent)
                if valid:
                    print_board()
                    ganador = check_winner()
                    if ganador is None:
                        turno = "X" if turno == "O" else "O"
                else:
                    print(f"El movimiento de {oponent} fue inválido, esperando su movimiento...")
            conn.close()
        except Exception as e:
            if ganador is None:
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
    global player, oponent, tictactoe, turno, ganador
    # Pedimos datos de configuración por consola
    local_ip = sys.argv[1]  # "0.0.0.0" para escuchar en todas las interfaces locales
    #local_port = int(input("¿En qué puerto quieres escuchar? (p.ej. 30000): ").strip())

    #remote_ip = input("IP remota del otro nodo (p.ej. 192.168.1.10): ").strip()
    #remote_port = int(input("Puerto remoto (p.ej. 30000): ").strip())

    local_port = int(sys.argv[2])
    remote_ip = sys.argv[3]
    remote_port = int(sys.argv[4])
    player = sys.argv[5]

    for row in range(3):
        for col in range(3):
            tictactoe[row][col] = '-'

    oponent = 'X'
    if player == 'X':
        oponent = 'O'

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
    print_board()
    if turno != player:
        print(f"Es turno de {turno}, esperando su movimiento...")
    while ganador is None:
        try:
            mensaje = ""
            if turno == player:
                print("Es tu turno, ingresa tu movimiento ejemplo 1,1 para la primera posicion: ", end="")
                mensaje = input("")
            if mensaje.strip():
                send_message(remote_ip, remote_port, mensaje)
                valid = make_move(mensaje, player)
                if valid:
                    print_board()
                    turno = "X" if player == "O" else "O"
                    ganador = check_winner()
                    if ganador is None and turno != player:
                        print(f"Es turno de {turno}, esperando su movimiento...")
                else:
                    print(f"Movimiento inválido, intenta de nuevo...")

        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n[SALIENDO] Deteniendo el chat...")
            if server_socket:
                server_socket.close()
                sys.exit(0)
    if ganador:
        print(f"¡El ganador es {ganador}!")
    if server_socket:
        server_socket.close()

if __name__ == "__main__":
    # Se debe ejecutar el script con los siguientes argumentos:
    # - IP local: es la dirección IP donde se escucharán las conexiones entrantes.
    # - Puerto local: es el puerto donde se escucharán las conexiones entrantes.
    # - IP remota: es la dirección IP del otro nodo.
    # - Puerto remoto: es el puerto del otro nodo.
    #
    # Ejemplo de ejecución para el primer jugador (X):
    #     python3 tictactoe.py 192.168.0.225 30000 192.168.0.124 30000 X
    # Ejemplo de ejecución para el segundo jugador (O):
    #     python3 tictactoe.py 192.168.0.124 30000 192.168.0.225 30000 O
    # 
    # En local, se puede usar los siguientes comandos:
    #
    # Ejemplo de ejecución para el primer jugador (X):
    #     python3 tictactoe.py 127.0.0.1 30000 127.0.0.1 30001 X
    # Ejemplo de ejecución para el segundo jugador (O):
    #     python3 tictactoe.py 127.0.0.1 30001 127.0.0.1 30000 O
    main()
