import socket

# Configuración del servidor
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = 20001
BUFFER_SIZE = 1024
ADDR = (LOCAL_IP, LOCAL_PORT)
message = "" # Variable para almacenar el mensaje a enviar

# Instancia del socket, AF_INET para IPv4 y SOCK_STREAM para TCP
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conexión al servidor, se debe indicar la dirección IP y el puerto
client_socket.connect(ADDR)  # connect to the server
print("Conexión establecida con el servidor!")

while message != 'end':
    try:
        # Escribir mensaje a enviar al servidor
        message = input("Cliente (Tú): ")

        # Enviar mensaje al servidor
        client_socket.send(message.encode())

        # Recibir respuesta del servidor
        data = client_socket.recv(BUFFER_SIZE).decode()

        # Mostrar en la terminal la respuesta del servidor
        print('Servidor -> ' + data)
    except KeyboardInterrupt:
        # Salir del bucle si se presiona Ctrl+C
        print("\nCliente cerrando conexión...")
        break
    except Exception as e:
        # Salir del bucle si ocurre un error inesperado
        print(f"Ocurrió un error: {e}")
        break

# Cerrar la conexión
client_socket.close()