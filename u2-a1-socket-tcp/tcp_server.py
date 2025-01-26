import socket

# Configuración del servidor
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = 20001
BUFFER_SIZE = 1024
ADDR = (LOCAL_IP, LOCAL_PORT)

# Crear el socket TCP, AF_INET para IPv4 y SOCK_STREAM para TCP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Enlazar el socket para escuchar mensajes de los clientes
server_socket.bind(ADDR)

# Configurar cuántos clientes puede escuchar el servidor simultáneamente
server_socket.listen(2)

# Aceptar la conexión entrante, conn es el socket para comunicarse con el cliente
print("Esperando conexión...")
conn, address = server_socket.accept()
print("Conexión establecida!" + str(address))

while True:
    try:
        # Recibir mensaje del cliente, el servidor no aceptará paquetes de datos mayores a 1024 bytes
        data = conn.recv(BUFFER_SIZE).decode()
        if not data:
            # Si no se recibe ningún dato, se cierra la conexión
            break
        print("Cliente -> " + str(data))
        data = input('Servidor (Tú): ')
        # Enviar datos al cliente
        conn.send(data.encode())
    except KeyboardInterrupt:
        # Salir del bucle si se presiona Ctrl+C
        print("\nServidor cerrando conexión...")
        break
    except Exception as e:
        # Salir del bucle si ocurre un error inesperado
        print(f"Ocurrió un error: {e}")
        break

# Cerrar la conexión
conn.close()