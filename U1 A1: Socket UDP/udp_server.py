import socket
from datetime import datetime

# Configuración del servidor
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = 20001
BUFFER_SIZE = 1024

# Crear el socket UDP, con with garantizamos que la conexión se cierra al finalizar el bloque
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_server_socket:

    # Enlazar el socket para escuchar mensajes de los clientes
    udp_server_socket.bind((LOCAL_IP, LOCAL_PORT))
    print("\nUDP server up and listening...\n")

    # Bucle para escuchar mensajes de los clientes y mostrarlos en consola
    while True:
        try:
            # Recibir mensaje del cliente
            bytes_address_pair = udp_server_socket.recvfrom(BUFFER_SIZE)

            # Decodificar el mensaje y obtener la dirección del cliente
            message = bytes_address_pair[0].decode().strip()
            address = bytes_address_pair[1]

            # Logs con timestamp y address del cliente para identificar el origen del mensaje
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] Message from {address}: {message}")
        except KeyboardInterrupt:
            # Salir del bucle si se presiona Ctrl+C
            print("\nServer shutting down gracefully...")
            break
        except Exception as e:
            # Salir del bucle si ocurre un error inesperado
            print(f"An error occurred: {e}")
            break