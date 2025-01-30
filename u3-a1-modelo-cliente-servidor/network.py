import logging
import socket
import multiprocessing
import queue
from typing import Optional

# Configuración del servidor
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = 20001

# Configuración básica del logger
logging.basicConfig(
    level=logging.DEBUG,  # Nivel de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Formato del mensaje
    handlers=[logging.StreamHandler()]  # Enviar logs a la consola
)

# Crear un logger
logger = logging.getLogger("App principal")

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
        logger.info("Configurando servidor...")
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
        logger.info("Starting servidor ...")
        self.server_thread.start()
        #print("Joining servidor ...")
        #self.server_thread.join()

    def terminate(self):
        """ Termina el servidor y espera a que el proceso termine. """
        logger.info("Terminando servidor...")
        self.stop_event.set()  # Activar la bandera para detener el proceso
        self.server_thread.join(timeout=5)  # Esperar a que el proceso termine
        if self.server_thread.is_alive():
            logger.warning("El proceso no terminó correctamente. Forzando terminación...")
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

        try:
            # Aceptar la conexión entrante, conn es el socket
            # para comunicarse con el cliente
            logger.info("Esperando conexión...")
            conn, addr = server_socket.accept()
            logger.info("Conexión establecida con: %s", addr)

            while True:
                # Recibir mensaje del cliente, el servidor no
                # aceptará paquetes de datos mayores a 1024 bytes
                data = conn.recv(buffer_size)
                if data:
                    msg = data.decode('utf-8')
                    #print(f"Mensaje recibido de {addr}: {msg}")
                    # Colocamos el mensaje en la cola con un tag 
                    # para identificar quién lo envió.
                    incoming_queue.put((addr, msg))

                data = "ACK"
                conn.send(data.encode())
                print("Servidor (Tú):")
                logger.info("Enviando ACK al cliente...")
        except KeyboardInterrupt:
            # Terminar hilo si se presiona Ctrl+C
            logger.warning("\n[KeyboardInterrupt] Servidor cerrando conexión...")
        except Exception as e:
            # Salir del bucle si ocurre un error inesperado
            logger.error("Ocurrió un error: %s", e)

class ClientTCP:

    def __init__(self, ip: str, port: int, buffer_size: Optional[int] = 1024):
        self.address = (ip, port)
        self.buffer_size = buffer_size
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)
        logger.info("Conexión establecida con el servidor!")

    def send_message(self, message: str):
        self.client_socket.send(message.encode())
        data = self.client_socket.recv(self.buffer_size).decode()
        return data

    def close(self):
        self.client_socket.close()

if __name__ == '__main__':
    server = ServerTCP(LOCAL_IP, LOCAL_PORT)
    server.start()

    # Verificar la cola de mensajes en el programa principal
    while server.server_thread.is_alive():
        try:
            # Intentar obtener un mensaje de la cola
            address, mensaje = server.incoming_queue.get(timeout=1)  # Espera 1 segundo
            print(f"{address}: {mensaje}")
        except queue.Empty:
            # Si no hay mensajes en la cola, continuar
            continue
        except KeyboardInterrupt:
            # Salir si se presiona Ctrl+C
            logger.info("\n[KeyboardInterrupt] Proceso de verificación de cola de mensajes terminado.")
            server.terminate() # no se porque no se ejecuta esto
            break

    if not server.server_thread.is_alive():
        logger.info("\nHilo del servidor terminado correctamente.")
