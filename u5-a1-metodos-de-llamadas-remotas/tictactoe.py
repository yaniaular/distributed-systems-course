#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import sys
import signal
import time
import re

# -------------------------------------------------------------------------
#                           CLASE: Tablero
# -------------------------------------------------------------------------
class Tablero:
    """
    Maneja la lógica de Tic-Tac-Toe: tablero, movimientos, verificación de ganador.
    """
    def __init__(self):
        # Inicializa el tablero de 3x3 con '-'
        self.tictactoe = [['-' for _ in range(3)] for _ in range(3)]

    def print_board(self, player):
        """
        Muestra el tablero en pantalla.
        """
        print("================")
        print(f"  [Player '{player}']\n Tablero actual:\n")
        for row in range(3):
            print("    ", end="")
            for col in range(3):
                print(self.tictactoe[row][col], end=" ")
            print("")
        print("================")

    def make_move(self, move_str, jugador):
        """
        Realiza un movimiento si es válido.
        move_str debe ser algo tipo "1,1" (fila,columna), con filas/columnas en [1..3].
        Retorna True si el movimiento fue válido; False de lo contrario.
        """
        pattern = re.compile(r'^[123],[123]$')
        move_str = move_str.strip()
        if not pattern.match(move_str):
            return False

        fila_str, col_str = move_str.split(",")
        row = int(fila_str) - 1
        col = int(col_str) - 1

        if self.tictactoe[row][col] == '-':
            self.tictactoe[row][col] = jugador
            return True
        else:
            return False

    def check_winner(self):
        """
        Verifica si hay un ganador. Retorna 'X', 'O' o None si no hay ganador.
        """
        # Revisar filas
        for row in range(3):
            if (self.tictactoe[row][0] == self.tictactoe[row][1] == self.tictactoe[row][2]
                and self.tictactoe[row][0] != '-'):
                return self.tictactoe[row][0]
        # Revisar columnas
        for col in range(3):
            if (self.tictactoe[0][col] == self.tictactoe[1][col] == self.tictactoe[2][col]
                and self.tictactoe[0][col] != '-'):
                return self.tictactoe[0][col]
        # Revisar diagonales
        if (self.tictactoe[0][0] == self.tictactoe[1][1] == self.tictactoe[2][2]
            and self.tictactoe[0][0] != '-'):
            return self.tictactoe[0][0]
        if (self.tictactoe[0][2] == self.tictactoe[1][1] == self.tictactoe[2][0]
            and self.tictactoe[0][2] != '-'):
            return self.tictactoe[0][2]

        return None


# -------------------------------------------------------------------------
#                           CLASE: Server
# -------------------------------------------------------------------------
class Server:
    """
    Clase encargada de crear el socket en modo servidor (bind + listen).
    Cuando llega un mensaje, llama al callback on_message(msg).
    """
    def __init__(self, local_ip, local_port, on_message_callback):
        self.local_ip = local_ip
        self.local_port = local_port
        self.on_message_callback = on_message_callback  # función o método a invocar cuando llegue data
        self.server_socket = None
        self._running = False

    def start(self):
        """
        Inicia el servidor en un hilo independiente para no bloquear la app principal.
        """
        self._running = True
        hilo = threading.Thread(target=self._run_server, daemon=True)
        hilo.start()

    def _run_server(self):
        """
        Lógica interna del servidor: bind, accept, recv.
        """
        # Crear socket TCP
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.local_ip, self.local_port))
        self.server_socket.listen(5)

        print(f"[SERVIDOR] Escuchando en {self.local_ip}:{self.local_port}")

        while self._running:
            try:
                conn, addr = self.server_socket.accept()
                data = conn.recv(1024)
                if data:
                    mensaje = data.decode('utf-8')
                    # Llamamos al callback definido para procesar el mensaje
                    self.on_message_callback(mensaje)
                conn.close()
            except Exception as e:
                if self._running:  # si está corriendo y no lo hemos detenido manualmente
                    print(f"[SERVIDOR] Error: {e}")
                break

    def stop(self):
        """
        Detiene el servidor cerrando el socket.
        """
        self._running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"[SERVIDOR] Error al cerrar socket: {e}")


# -------------------------------------------------------------------------
#                           CLASE: Client
# -------------------------------------------------------------------------
class Client:
    """
    Clase para enviar mensajes a un nodo remoto (TCP).
    """
    def send_message(self, remote_ip, remote_port, mensaje):
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


# -------------------------------------------------------------------------
#                           MANEJO DE SEÑALES
# -------------------------------------------------------------------------
def signal_handler(sig, frame):
    """
    Manejador de señales para Ctrl + C (SIGINT) o SIGTERM.
    Cierra el programa.
    """
    print("\n[SALIR] Saliendo de la aplicación...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# -------------------------------------------------------------------------
#                              FUNCIÓN MAIN
# -------------------------------------------------------------------------
def main():
    """
    Flujo principal:
    1) Se leen parámetros de línea de comando: IP local, puerto local, IP remota, puerto remoto y quién es X u O.
    2) Se configura el tablero, el servidor y el cliente.
    3) Se maneja el bucle de turnos.
    """
    if len(sys.argv) < 6:
        print(f"Uso: {sys.argv[0]} <IP_local> <puerto_local> <IP_remota> <puerto_remoto> <X|O>")
        sys.exit(1)

    local_ip = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_ip = sys.argv[3]
    remote_port = int(sys.argv[4])
    player = sys.argv[5]

    # Determinar quién es el oponente
    if player not in ["X", "O"]:
        print("El quinto argumento debe ser 'X' o 'O'")
        sys.exit(1)
    oponent = "O" if player == "X" else "X"

    # Variables de estado del juego
    turno = "X"
    ganador = None

    # Creamos el tablero de juego
    tablero = Tablero()

    # ---------------------------------------------------------------------
    # Definimos la función callback que el servidor llama cuando recibe data
    # ---------------------------------------------------------------------
    def on_message_received(mensaje):
        nonlocal turno, ganador
        # El oponente ha hecho un movimiento
        valid = tablero.make_move(mensaje, oponent)
        if valid:
            tablero.print_board(player)
            ganador = tablero.check_winner()
            if ganador is None:
                # Cambiar turno
                turno = "X" if turno == "O" else "O"
            else:
                # Hay ganador
                pass
        else:
            print(f"Movimiento inválido recibido de {oponent} -> '{mensaje}'")

    # Iniciamos el servidor
    server = Server(local_ip, local_port, on_message_received)
    server.start()
    time.sleep(1)  # Esperar a que el servidor se inicie

    # Creamos el cliente
    client = Client()

    # Mensaje inicial
    print(f"\n[EJECUCIÓN] Eres '{player}'. Te conectas a {remote_ip}:{remote_port}.\n")
    print("Usa Ctrl + C para salir.\n")

    # Mostramos el tablero al principio
    tablero.print_board(player)
    if turno != player:
        print(f"Es turno de {turno}, esperando su movimiento...")

    # Bucle principal de turnos
    while ganador is None:
        try:
            # Si es turno nuestro, pedimos input
            if turno == player:
                print("Ingresa tu movimiento (ej. 1,1): ", end="")
                sys.stdout.flush()
                move_str = sys.stdin.readline().strip()  # para leer con posibilidad de Ctrl+C

                if move_str:
                    # Enviamos al oponente
                    client.send_message(remote_ip, remote_port, move_str)
                    # Intentamos hacer el movimiento local
                    valid = tablero.make_move(move_str, player)
                    if valid:
                        tablero.print_board(player)
                        ganador = tablero.check_winner()
                        if ganador is None:
                            turno = "X" if player == "O" else "O"
                            if turno != player:
                                print(f"Es turno de {turno}, esperando su movimiento...")
                        else:
                            break
                    else:
                        print("Movimiento inválido. Intenta de nuevo...")
            else:
                # No es nuestro turno; solo esperamos
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n[SALIENDO] Deteniendo el juego...")
            server.stop()
            sys.exit(0)

    # Si hemos salido del while con un ganador
    if ganador:
        print(f"¡El ganador es {ganador}!")
    else:
        print("Juego terminado sin ganador.")
    
    # Cerrar servidor al final
    server.stop()


if __name__ == "__main__":
    """
    Ejemplo de ejecución para el primer jugador (X):
        python3 tictactoe.py 192.168.0.225 30000 192.168.0.124 30000 X

    Ejemplo de ejecución para el segundo jugador (O):
        python3 tictactoe.py 192.168.0.124 30000 192.168.0.225 30000 O

    En local, se puede usar:
        # Jugador X:
        python3 tictactoe.py 127.0.0.1 30000 127.0.0.1 30001 X
        # Jugador O:
        python3 tictactoe.py 127.0.0.1 30001 127.0.0.1 30000 O
    """
    main()
