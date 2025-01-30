import socket
import multiprocessing
import queue
from typing import Tuple, Optional


# Configuración del servidor
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = 20001

class ServerTCP:
    """ Clase que representa un servidor TCP.

    Atributos:
        incoming_queue (multiprocessing.Queue): Cola de mensajes recibidos.
        server_thread (multiprocessing.Process): Proceso del servidor.
        address (Tuple[str, int]): Dirección IP y puerto del servidor.
        buffer_size (int): Tamaño del buffer para recibir mensajes.
        maximum_connections (int): Número máximo de conexiones de clientes simultáneas.
    """

    def __init__(self, 
                 ip: str, 
                 port: int, 
                 buffer_size: Optional[int] = 1024,
                 maximum_connections: Optional[int] = 3):
        print("Iniciando servidor...")
        self.incoming_queue = multiprocessing.Queue()
        self.address = (ip, port)
        self.buffer_size = buffer_size
        self.maximum_connections = maximum_connections
        self.stop_event = multiprocessing.Event() # Bandera para detener el proceso
        self.server_thread = multiprocessing.Process(
            target=self.server_process,
            args=(self.incoming_queue,
                  self.address,
                  self.buffer_size,
                  self.maximum_connections),
            daemon=True
        )

    def start(self):
        """ Inicia el servidor en un proceso aparte. """
        print("Starting servidor ...")
        self.server_thread.start()

    def terminate(self):
        """ Termina el servidor y espera a que el proceso termine. """
        print("Terminando servidor...")
        self.stop_event.set()  # Activar la bandera para detener el proceso
        self.server_thread.join(timeout=5)  # Esperar a que el proceso termine
        if self.server_thread.is_alive():
            print("El proceso no terminó correctamente. Forzando terminación...")
            self.server_thread.terminate()  # Forzar la terminación si no responde
        self.server_thread.join()  # Esperar a que el proceso termine completamente

    @staticmethod
    def server_process(incoming_queue, address, buffer_size, maximum_connections):
        """ Proceso que se encarga de escuchar en (ip:port) usando TCP.
        
        Cada mensaje que reciba lo coloca en 'incoming_queue' para 
        que la interfaz u otro proceso pueda acceder a él.
        """
        # Crear el socket TCP, AF_INET para IPv4 y SOCK_STREAM para TCP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Enlazar el socket para escuchar mensajes de los clientes
        server_socket.bind(address)

        # Configurar cuántos clientes puede escuchar el servidor simultáneamente
        server_socket.listen(maximum_connections)

        while True:
            try:
                # Aceptar la conexión entrante, conn es el socket
                # para comunicarse con el cliente
                print("Esperando conexión...")
                conn, addr = server_socket.accept()
                print(f"Conexión establecida con {addr}")

                # Recibir mensaje del cliente, el servidor no
                # aceptará paquetes de datos mayores a 1024 bytes
                data = conn.recv(buffer_size)
                if data:
                    msg = data.decode('utf-8')
                    print(f"Mensaje recibido de {addr}: {msg}")
                    # Colocamos el mensaje en la cola con un tag 
                    # para identificar quién lo envió.
                    incoming_queue.put((addr, msg))

                data = "ACK"
                conn.send(data.encode())
                print(f"ACK enviado a {addr}")
            except KeyboardInterrupt:
                # Salir del bucle si se presiona Ctrl+C
                print("\n[KeyboardInterrupt] Servidor cerrando conexión...")
                break
            except Exception as e:
                # Salir del bucle si ocurre un error inesperado
                print(f"Ocurrió un error: {e}")
                break

        print("Termina server process...")
        # Cerrar la conexión
        #conn.close()

if __name__ == '__main__':
    server = ServerTCP(LOCAL_IP, LOCAL_PORT)
    server.start()

    # Verificar la cola de mensajes en el programa principal
    while server.server_thread.is_alive():
        try:
            # Intentar obtener un mensaje de la cola
            address, mensaje = server.incoming_queue.get(timeout=1)  # Espera 1 segundo
            print(f"Mensaje recibido en el programa principal: {address} -> {mensaje}")
        except queue.Empty:
            # Si no hay mensajes en la cola, continuar
            continue
        except KeyboardInterrupt:
            # Salir si se presiona Ctrl+C
            print("\n[KeyboardInterrupt] Programa principal terminado.")
            server.terminate() # no se porque no se ejecuta esto
            break

    if not server.server_thread.is_alive():
        print("Hilo del servidor terminado correctamente.")
        