import network

if __name__ == '__main__':
    
    client_socket = network.ClientTCP(network.LOCAL_IP, network.LOCAL_PORT)
    message = ""

    while message != 'end':
        try:
            # Escribir mensaje a enviar al servidor
            message = input("Cliente (Tú): ")

            # Enviar mensaje al servidor
            data = client_socket.send_message(message)

            # Mostrar en la terminal la respuesta del servidor
            print('Servidor: ' + data)
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
