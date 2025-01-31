import logging
import sys
import socket
import multiprocessing
import queue
from typing import Optional
import tkinter as tk
from tkinter import messagebox
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout
)

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

class ChatroomWindows(QMainWindow):
    def __init__(self, nickname: str):
        super().__init__()

        # Guardar el nickname del usuario
        self.nickname = nickname

        # Crear el servidor TCP
        self.server = ServerTCP(LOCAL_IP)
        self.server.start()
        # Guardar el servidor en el diccionario de usuarios
        USERS[nickname] = {"server": self.server, "open_chats": {}}

        # Crear la ventana principal
        self.setWindowTitle(f"Chatroom de {nickname}")
        self.setGeometry(100, 100, 300, 200)

        # Crear un widget central y un layout vertical
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Título de la ventana
        lbl_titulo = QLabel(f"Hola {nickname}! Usuarios conectados:", self)
        lbl_titulo.setFont(self.get_font(14))
        layout.addWidget(lbl_titulo)

        # Frame para la lista de usuarios
        self.frame_usuarios = QWidget()
        self.frame_usuarios.setLayout(QVBoxLayout())
        layout.addWidget(self.frame_usuarios)

        # Actualizar la lista de usuarios por primera vez
        self.update_user_list(nickname)

        # Programar la actualización automática cada 2 segundos
        self.timer = QTimer()
        self.timer.timeout.connect(lambda: self.update_user_list(nickname))
        self.timer.start(2000)  # 2000 ms = 2 segundos

    def update_user_list(self, nickname):
        """ Actualiza la lista de usuarios conectados. """
        # Limpiar el frame de usuarios
        for i in reversed(range(self.frame_usuarios.layout().count())):
            self.frame_usuarios.layout().itemAt(i).widget().setParent(None)

        # Mostrar cada usuario con un botón "Abrir conversación"
        for destinatario, config in USERS.items():
            if destinatario == nickname:
                continue

            frame_destinatario = QWidget()
            frame_destinatario.setLayout(QHBoxLayout())

            lbl_usuario = QLabel(destinatario, frame_destinatario)
            lbl_usuario.setFont(self.get_font(12))
            frame_destinatario.layout().addWidget(lbl_usuario)

            btn_conversacion = QPushButton("Abrir conversación", frame_destinatario)
            btn_conversacion.setFont(self.get_font(10))
            btn_conversacion.clicked.connect(lambda _, n=nickname, u=destinatario, c=config.get("server"): self.open_chat_window(n, u, c))
            frame_destinatario.layout().addWidget(btn_conversacion)

            self.frame_usuarios.layout().addWidget(frame_destinatario)

    def open_chat_window(self, nickname: str, destinatario: str, destinatario_config: ServerTCP):
        """ Abre una ventana de chat con el usuario seleccionado. """
        # Crear una nueva ventana para el chat
        ventana_chat = QMainWindow()
        ventana_chat.setWindowTitle(f"[{nickname}] Chat con {destinatario}")
        ventana_chat.setGeometry(100, 100, 400, 500)

        # Validar que no exista un chat abierto con el destinatario
        if destinatario in USERS[nickname]["open_chats"]:
            QMessageBox.warning(ventana_chat, "Advertencia", f"Ya tienes un chat abierto con {destinatario}")
            return
        # Crear un socket cliente para hablar con el destinatario, es decir
        # nos conectamos al servidor del destinatario
        client_socket = ClientTCP(destinatario_config.ip, destinatario_config.port)
        USERS[nickname]["open_chats"] = {destinatario: [client_socket, ventana_chat]}

        # Widget central y layout
        central_widget = QWidget()
        ventana_chat.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Área de visualización de mensajes
        self.texto_message = QTextEdit(ventana_chat)
        self.texto_message.setReadOnly(True)  # Deshabilitar edición del área de mensajes
        self.texto_message.setFont(self.get_font(12))
        layout.addWidget(self.texto_message)

        # Cuadro de texto para escribir mensajes
        frame_entrada = QWidget()
        frame_entrada.setLayout(QHBoxLayout())

        self.entry_message = QLineEdit(frame_entrada)
        self.entry_message.setFont(self.get_font(12))
        frame_entrada.layout().addWidget(self.entry_message)

        # Botón para enviar mensajes
        btn_enviar = QPushButton("Enviar", frame_entrada)
        btn_enviar.setFont(self.get_font(12))
        btn_enviar.clicked.connect(lambda: self.send_message(destinatario))
        frame_entrada.layout().addWidget(btn_enviar)

        layout.addWidget(frame_entrada)

        ventana_chat.show()

    def send_message(self, usuario):
        """ Envía un mensaje y lo muestra en el área de mensajes. """
        message = self.entry_message.text()
        if message.strip():  # Verificar que el mensaje no esté vacío
            # Mostrar el mensaje en el área de mensajes
            self.texto_message.append(f"Tú: {message}")
            self.entry_message.clear()

            # Aquí puedes agregar la lógica para enviar el mensaje al servidor
            # Por ejemplo: self.server.enviar_mensaje(usuario, mensaje)

    def get_font(self, size):
        """ Retorna una fuente con el tamaño especificado. """
        font = self.font()
        font.setPointSize(size)
        return font
        

class NicknameWindow(QMainWindow):
    """ Ventana secundaria para ingresar el nickname. """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ingresar Nickname")
        self.setGeometry(200, 200, 300, 150)

        # Widget central y layout principal
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Etiqueta
        self.label_instruction = QLabel("Ingresa tu nickname:", self)
        layout.addWidget(self.label_instruction)

        # Campo de texto
        self.txt_nickname = QLineEdit(self)
        layout.addWidget(self.txt_nickname)

        # Botón para confirmar
        self.btn_confirm = QPushButton("Confirmar", self)
        self.btn_confirm.clicked.connect(self.confirm_nickname)
        layout.addWidget(self.btn_confirm)

    def confirm_nickname(self):
        """ Obtiene el texto, muestra un mensaje y cierra la ventana. """
        nickname = self.txt_nickname.text().strip()
        if not nickname:
            QMessageBox.warning(self, "Advertencia", "Por favor, ingresa un nickname.")
            return
        
        if nickname in USERS:
            QMessageBox.warning(self, "Advertencia", "El nickname ya está en uso.")
            return

        QMessageBox.information(self, "Información", f"Bienvenido {nickname}")
        self.close()

        self.chat_room_windows = ChatroomWindows(nickname)
        self.chat_room_windows.show()

class MainWindow(QMainWindow):
    """ Ventana principal con dos botones. """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ventana Principal")
        self.setGeometry(100, 100, 300, 200)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.btn_nickname = QPushButton("Conectarte al chatroom", self)
        self.btn_nickname.clicked.connect(self.ask_nickname_window)
        layout.addWidget(self.btn_nickname)

        self.btn_list_users = QPushButton("Revisar usuarios", self)
        self.btn_list_users.clicked.connect(self.list_users)
        layout.addWidget(self.btn_list_users)

        self.btn_cerrar = QPushButton("Cerrar todo", self)
        self.btn_cerrar.clicked.connect(self.close_all)
        layout.addWidget(self.btn_cerrar)

    def close_all(self):
        """ Cierra todos los servidores, clientes y ventanas. """
        for user, config in USERS.items():
            server = config.get("server")
            for dest_name, values in config.get("open_chats", {}).items():
                cliente = values[0]
                cliente.close()
                del cliente
                ventana_chat = values[1]
                ventana_chat.close()
                del ventana_chat
            if server:
                server.terminate()
                del server
        USERS.clear()
        self.close()

    def ask_nickname_window(self):
        """ Crea y muestra la ventana para ingresar nickname. """
        self.nickname_window = NicknameWindow()
        self.nickname_window.show()

    def list_users(self):
        """ Muestra la información de los usuarios. """
        for user, config in USERS.items():
            print(user, config)

def main():
    app = QApplication(sys.argv)
    ventana = MainWindow()
    ventana.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

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
