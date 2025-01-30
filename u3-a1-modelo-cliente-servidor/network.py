import logging
import socket
import multiprocessing
import queue
from typing import Optional
import tkinter as tk
from tkinter import messagebox

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

# Diccionario para almacenar los usuarios conectados
USERS = {}
AVAILABLE_PORTS = set(range(20001, 20011))

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
                 buffer_size: Optional[int] = 1024,
                 maximum_connections: Optional[int] = 3):
        logger.info("Configurando servidor...")
        self.ip = ip
        self.port = self.get_free_port()
        self.incoming_queue = multiprocessing.Queue()
        self.address = (ip, self.port)
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

    def get_free_port(self):
        """
        Retorna un puerto libre del conjunto de puertos disponibles.
        Si no hay puertos disponibles, lanza un error.
        """
        if not AVAILABLE_PORTS:
            raise RuntimeError("No hay puertos disponibles")
        # Extrae un puerto (y lo quita del conjunto)
        return AVAILABLE_PORTS.pop()

    def terminate(self):
        """ Termina el servidor y espera a que el proceso termine. """
        if self.server_thread.is_alive():
            logger.info("Terminando servidor...")
            self.stop_event.set()  # Activar la bandera para detener el proceso
            self.server_thread.join(timeout=5)  # Esperar a que el proceso termine
            if self.server_thread.is_alive():
                logger.warning("El proceso no terminó correctamente. Forzando terminación...")
                self.server_thread.terminate()  # Forzar la terminación si no responde
            self.server_thread.join()  # Esperar a que el proceso termine completamente
            AVAILABLE_PORTS.add(self.port)  # Devolver el puerto al conjunto

    def __del__(self):
        """ Método que se ejecuta al liberar la memoria del objeto. """
        self.terminate()

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
    """ Clase que representa un cliente TCP

    Atributos:
        address (Tuple[str, int]): Dirección IP y puerto del servidor.
        buffer_size (int): Tamaño del buffer para recibir mensajes.
        client_socket (socket.socket): Socket del cliente.
    """

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

class ChatroomApp:
    """ Interfaz gráfica para el chatroom. """

    def __init__(self, root):
        self.root = root
        self.root.title("Chatroom")
        self.root.geometry("300x200")

        # Botón para entrar al chatroom
        self.btn_entrar = tk.Button(
            root,
            text="Entrar al chatroom",
            font=("Arial", 14),
            command=self.abrir_ventana_nickname
        )
        self.btn_entrar.pack(pady=20)

        # Botón para revisar información de los usuarios
        btn_check_users = tk.Button(
            root,
            text="Revisar usuarios",
            font=("Arial", 14),
            command=self.check_users
        )
        btn_check_users.pack(pady=20)

    def check_users(self):
        for user, config in USERS.items():
            print(user, config)

    def abrir_ventana_nickname(self):
        """ Abre una ventana para solicitar el nickname. """
        self.ventana_nickname = tk.Toplevel(self.root)
        self.ventana_nickname.title("Nickname")
        self.ventana_nickname.geometry("300x150")

        # Etiqueta y campo de entrada para el nickname
        lbl_nickname = tk.Label(
            self.ventana_nickname, 
            text="Ingresa tu nickname:",
            font=("Arial", 12)
        )
        lbl_nickname.pack(pady=10)

        self.entry_nickname = tk.Entry(
            self.ventana_nickname,
            font=("Arial", 12)
        )
        self.entry_nickname.pack(pady=10)

        # Botón para confirmar el nickname
        btn_confirmar = tk.Button(
            self.ventana_nickname,
            text="Confirmar",
            font=("Arial", 12),
            command=self.crear_servidor
        )
        btn_confirmar.pack(pady=10)

    def crear_servidor(self):
        """ Crea el servidor TCP con el nickname proporcionado. """
        nickname = self.entry_nickname.get()
        if not nickname:
            messagebox.showerror("Error", "Debes ingresar un nickname.")
            return

        # Cerrar la ventana de nickname
        self.ventana_nickname.destroy()

        # Mostrar mensaje de confirmación
        messagebox.showinfo("Chatroom", f"Bienvenido, {nickname}!")

        # Crear el servidor TCP
        server = ServerTCP(LOCAL_IP)
        server.start()

        USERS[nickname] = {"server": server, "chat_abiertos": {}}

        # Abrir la ventana de usuarios conectados
        self.abrir_ventana_usuarios(nickname)

    def abrir_ventana_usuarios(self, nickname):
        """ Abre una ventana que muestra la lista de usuarios conectados. """
        self.ventana_usuarios = tk.Toplevel(self.root)
        self.ventana_usuarios.title(f"Ventana de {nickname}")
        self.ventana_usuarios.geometry("400x300")

        # Título de la ventana
        lbl_titulo = tk.Label(
            self.ventana_usuarios, 
            text=f"Hola {nickname}! Usuarios conectados:",
            font=("Arial", 14)
        )
        lbl_titulo.pack(pady=10)

        # Mostrar cada usuario con un botón "Abrir conversación"
        for usuario, config in USERS.items():
            if usuario == nickname:
                continue
            frame_usuario = tk.Frame(self.ventana_usuarios)
            frame_usuario.pack(pady=5)

            lbl_usuario = tk.Label(
                frame_usuario, 
                text=usuario, 
                font=("Arial", 12)
            )
            lbl_usuario.pack(side=tk.LEFT, padx=10)

            btn_conversacion = tk.Button(
                frame_usuario,
                text="Abrir conversación",
                font=("Arial", 10),
                command=lambda n=nickname, u=usuario, c=config.get("server"): self.abrir_conversacion(n,u,c)
            )
            btn_conversacion.pack(side=tk.RIGHT)

    def abrir_conversacion(self, nickname: str, destinatario: str, config: ServerTCP):
        """ Abre una ventana de chat con el usuario seleccionado. """
        # Crear una nueva ventana para el chat
        ventana_chat = tk.Toplevel(self.root)
        ventana_chat.title(f"[{nickname}] Chat con {destinatario}")
        ventana_chat.geometry("400x500")

        client_socket = ClientTCP(config.ip, config.port)
        USERS[nickname]["chat_abiertos"] = {destinatario: client_socket}

        # Área de visualización de mensajes
        frame_mensajes = tk.Frame(ventana_chat)
        frame_mensajes.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(frame_mensajes)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.texto_mensajes = tk.Text(
            frame_mensajes, 
            yscrollcommand=scrollbar.set, 
            state=tk.DISABLED,  # Deshabilitar edición del área de mensajes
            font=("Arial", 12)
        )
        self.texto_mensajes.pack(fill=tk.BOTH, expand=True)

        scrollbar.config(command=self.texto_mensajes.yview)

        # Cuadro de texto para escribir mensajes
        frame_entrada = tk.Frame(ventana_chat)
        frame_entrada.pack(fill=tk.X, padx=10, pady=10)

        self.entry_mensaje = tk.Entry(
            frame_entrada, 
            font=("Arial", 12)
        )
        self.entry_mensaje.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        # Botón para enviar mensajes
        btn_enviar = tk.Button(
            frame_entrada, 
            text="Enviar", 
            font=("Arial", 12), 
            command=lambda: self.enviar_mensaje(destinatario)
        )
        btn_enviar.pack(side=tk.RIGHT)

        # Asociar la tecla "Enter" al envío de mensajes
        self.entry_mensaje.bind("<Return>", lambda event: self.enviar_mensaje(destinatario))

    def enviar_mensaje(self, usuario):
        """ Envía un mensaje y lo muestra en el área de mensajes. """
        mensaje = self.entry_mensaje.get()
        if mensaje.strip():  # Verificar que el mensaje no esté vacío
            # Mostrar el mensaje en el área de mensajes
            self.texto_mensajes.config(state=tk.NORMAL)  # Habilitar edición temporalmente
            self.texto_mensajes.insert(tk.END, f"Tú: {mensaje}\n")
            self.texto_mensajes.config(state=tk.DISABLED)  # Deshabilitar edición nuevamente
            self.texto_mensajes.yview(tk.END)  # Desplazar al final del texto

            # Limpiar el cuadro de texto
            self.entry_mensaje.delete(0, tk.END)

            # Aquí puedes agregar la lógica para enviar el mensaje al servidor
            # Por ejemplo: self.server.enviar_mensaje(usuario, mensaje)

if __name__ == '__main__':


    root = tk.Tk()
    app = ChatroomApp(root)
    root.mainloop()

    """
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
    else:
        logger.warning("\nHilo del servidor no terminó correctamente.")
        server.terminate()
        logger.info("Servidor terminado forzosamente.")
    """
