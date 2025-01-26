import socket

# Configuración del servidor
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = 20001
ADDR = (LOCAL_IP, LOCAL_PORT)
message = "" # Variable para almacenar el mensaje a enviar

# Bucle para enviar mensajes al servidor
# El cliente puede enviar mensajes hasta que escriba "end"
while message != "end": 
    try:
        # Crear el socket UDP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = input("Enter message to send to server: ")
        bytes_to_send = str.encode(message)
        # Se indica el mensaje y el destinatario
        client_socket.sendto(bytes_to_send, ADDR)
    except KeyboardInterrupt:
        # Salir del bucle si se presiona Ctrl+C
        print("\nClient shutting down gracefully...")
        break
    except Exception as e:
        # Salir del bucle si ocurre un error inesperado
        print(f"An error occurred: {e}")
        break