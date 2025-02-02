import logging
import sys
import socket
import time
import multiprocessing
import queue
from typing import Optional, Dict, Tuple
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout
)

# Diccionario para almacenar los usuarios conectados
USERS = {}
USERS_CHATROOMS = {}
CHAT_MESSAGES = {}
USERS_CHATROOMS_BY_ADDR = {}

# Configuración del servidor
LOCAL_IP = "127.0.0.1"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Crear un logger
logger = logging.getLogger("App principal")

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
                 name: str,
                 ip: str, 
                 buffer_size: Optional[int] = 1024,
                 maximum_connections: Optional[int] = 3):
        logger.info("Configurando servidor...")
        self.name = name
        self.ip = ip
        self.port = self.get_free_port()
        print(f"[{self.name}]: Usando IP: {self.ip} - Usando puerto: {self.port}")
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

    def get_free_port(self):
        """
        Retorna un puerto libre del conjunto de puertos disponibles.
        Si no hay puertos disponibles, lanza un error.
        """
        if not AVAILABLE_PORTS:
            raise RuntimeError("No hay puertos disponibles")
        # Extrae un puerto (y lo quita del conjunto disponible)
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
                # Recibir mensaje del cliente
                data = conn.recv(buffer_size)
                if data:
                    msg = data.decode('utf-8')
                    # Colocar el mensaje en la cola de mensajes entrantes
                    # para poder acceder a él desde otro proceso
                    incoming_queue.put((msg, addr))
                    logger.info(f"Mensaje recibido de {addr}: {msg}")

                data = "ACK"
                conn.send(data.encode())
                logger.info("Enviando ACK al cliente...")
        except KeyboardInterrupt:
            logger.warning("\n[KeyboardInterrupt] Servidor cerrando conexión...")
        except Exception as e:
            logger.error("Ocurrió un error: %s", e)

class ClientTCP:
    """ Clase que representa un cliente TCP

    Atributos:
        address (Tuple[str, int]): Dirección IP y puerto del servidor.
        buffer_size (int): Tamaño del buffer para recibir mensajes.
        client_socket (socket.socket): Socket del cliente.
    """

    def __init__(self, name: str, ip: str, port: int, buffer_size: Optional[int] = 1024):
        self.name = name
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
        self.sender_nickname = nickname
        USERS[self.sender_nickname] = UserInfo(nickname, self)

        self.chat_windows = {} # Diccionario para almacenar las ventanas de chat que tiene abiertas el sender
        self.text_box = {} # Diccionario para almacenar los QTextEdit de cada chat
        self.entry_message = {} # Diccionario para almacenar los QLineEdit de cada chat

        self.setWindowTitle(f"Chatroom de {self.sender_nickname}")
        self.setGeometry(100, 100, 300, 200)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        lbl_titulo = QLabel(f"Hola {self.sender_nickname}! Usuarios conectados:", self)
        lbl_titulo.setFont(self.get_font(14))
        layout.addWidget(lbl_titulo)

        self.frame_usuarios = QWidget()
        self.frame_usuarios.setLayout(QVBoxLayout())
        layout.addWidget(self.frame_usuarios)

        self.update_user_list()

        self.timer = QTimer()
        self.timer.timeout.connect(lambda: self.update_user_list())
        self.timer.start(1000)

    def update_user_list(self):
        """ Actualiza la lista de usuarios conectados. """
        for i in reversed(range(self.frame_usuarios.layout().count())):
            self.frame_usuarios.layout().itemAt(i).widget().setParent(None)

        for recipient_nickname in USERS.keys():
            if self.sender_nickname == recipient_nickname:
                continue

            frame_destinatario = QWidget()
            frame_destinatario.setLayout(QHBoxLayout())

            lbl_usuario = QLabel(recipient_nickname, frame_destinatario)
            lbl_usuario.setFont(self.get_font(12))
            frame_destinatario.layout().addWidget(lbl_usuario)

            btn_conversacion = QPushButton("Abrir conversación", frame_destinatario)
            btn_conversacion.setFont(self.get_font(10))
            btn_conversacion.clicked.connect(
                lambda _, u=recipient_nickname, s=self.sender_nickname: self.open_chat(u, s))
            frame_destinatario.layout().addWidget(btn_conversacion)

            self.frame_usuarios.layout().addWidget(frame_destinatario)

    def open_chat(self, recipient_nickname: str, sender_nickname: Optional[str] = None):
        if sender_nickname is None:
            sender_nickname = self.sender_nickname

        self.create_window_chat(recipient_nickname, sender_nickname)

    def create_window_chat(self, recipient_nickname: str, sender_nickname: Optional[str] = None):
        if sender_nickname is None:
            sender_nickname = self.sender_nickname

        # Crear una nueva ventana para el chat
        self.chat_windows[recipient_nickname] = QMainWindow()
        self.chat_windows[recipient_nickname].setWindowTitle(
            f"[{sender_nickname}] Chat con {recipient_nickname}")
        self.chat_windows[recipient_nickname].setGeometry(100, 100, 400, 500)

        central_widget = QWidget()
        self.chat_windows[recipient_nickname].setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Área de visualización de mensajes
        self.text_box[recipient_nickname] = QTextEdit(self.chat_windows[recipient_nickname])
        self.text_box[recipient_nickname].setReadOnly(True)
        self.text_box[recipient_nickname].setFont(self.get_font(12))
        layout.addWidget(self.text_box[recipient_nickname])

        # Cuadro de texto para escribir mensajes
        frame_entrada = QWidget()
        frame_entrada.setLayout(QHBoxLayout())

        self.entry_message[recipient_nickname] = QLineEdit(frame_entrada)
        self.entry_message[recipient_nickname].setFont(self.get_font(12))
        frame_entrada.layout().addWidget(self.entry_message[recipient_nickname])

        # Botón para enviar mensajes
        btn_enviar = QPushButton("Enviar", frame_entrada)
        btn_enviar.setFont(self.get_font(12))
        btn_enviar.clicked.connect(lambda: self.send_message(recipient_nickname))
        frame_entrada.layout().addWidget(btn_enviar)

        layout.addWidget(frame_entrada)
        self.chat_windows[recipient_nickname].show()

    def send_message(self, recipient_nickname: str):
        """ Envía un mensaje y lo muestra en el área de mensajes. """
        message = self.entry_message[recipient_nickname].text()
        if message.strip():  # Verificar que el mensaje no esté vacío

            # Mostrar el mensaje en el área de mensajes
            self.text_box[recipient_nickname].append(f"Tú: {message}")
            self.entry_message[recipient_nickname].clear()

            sender_user_info = USERS[self.sender_nickname] #yani
            recipient_user_info = USERS[recipient_nickname] #paco

            chatroom_recipient = None
            if self.sender_nickname not in recipient_user_info.tcp_servers: # si el recipient no tiene un servidor para recibir mensajes del sender, hay que crearlo
                server = ServerTCP(f"server_of_{recipient_nickname}_to_receive_messages_from_{self.sender_nickname}", LOCAL_IP)
                server.start()
                recipient_user_info.tcp_servers[self.sender_nickname] = server
                time.sleep(1)
                chatroom_recipient = USERS_CHATROOMS[recipient_nickname]
                chatroom_recipient.open_chat(recipient_nickname=self.sender_nickname,sender_nickname=recipient_nickname)
                recipient_user_info.check_incoming_messages_from[self.sender_nickname] = CheckIncomingMessages(server, chatroom_recipient)

            if recipient_nickname not in sender_user_info.tcp_servers: # si el sender no tiene un servidor para recibir mensajes del recipient, hay que crearlo
                server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_messages_from_{recipient_nickname}", LOCAL_IP)
                server.start()
                sender_user_info.tcp_servers[recipient_nickname] = server
                time.sleep(1)
                sender_user_info.check_incoming_messages_from[recipient_nickname] = CheckIncomingMessages(server, self)

            if recipient_nickname not in sender_user_info.tcp_clients: # si el sender no tiene creado un cliente para escribirle al recipient, hay que crearlo
                recipient_user_server_for_sender = recipient_user_info.tcp_servers[self.sender_nickname]
                client_socket = ClientTCP(f"client_of_{self.sender_nickname}_to_send_messages_to_{recipient_nickname}", recipient_user_server_for_sender.ip, recipient_user_server_for_sender.port)
                sender_user_info.tcp_clients[recipient_nickname] = client_socket
                USERS_CHATROOMS_BY_ADDR[client_socket.client_socket.getsockname()] = self

            if self.sender_nickname not in recipient_user_info.tcp_clients: # si el recipient no tiene creado un cliente para escribirle al sender, hay que crearlo
                sender_user_server_for_recipient = sender_user_info.tcp_servers[recipient_nickname]
                client_socket = ClientTCP(f"client_of_{recipient_nickname}_to_send_messages_to_{self.sender_nickname}", sender_user_server_for_recipient.ip, sender_user_server_for_recipient.port)
                recipient_user_info.tcp_clients[self.sender_nickname] = client_socket

                if chatroom_recipient is not None:
                    USERS_CHATROOMS_BY_ADDR[client_socket.client_socket.getsockname()] = chatroom_recipient

            client_socket = sender_user_info.tcp_clients[recipient_nickname]
            data = client_socket.send_message(message)
            print('Servidor: ' + data)

    def get_font(self, size):
        """ Retorna una fuente con el tamaño especificado. """
        font = self.font()
        font.setPointSize(size)
        return font

class CheckIncomingMessages:
    def __init__(self, server: ServerTCP, chatroom: ChatroomWindows):
        self.server = server
        self.chatroom = chatroom
        self.timer = QTimer(self.chatroom)
        self.timer.timeout.connect(self.check_incoming_messages)
        self.timer.start(100)

    def check_incoming_messages(self):
        try:
            # Intentar obtener un mensaje de la cola
            mensaje, address = self.server.incoming_queue.get_nowait()
            
            # Obtener el chatroom de la persona que le envió el mensaje a este self.server
            # esto es para obtener el nickname después
            chat_window = USERS_CHATROOMS_BY_ADDR.get(address)
            
            # Nickname de la persona que le envió el mensaje a este self.server
            sender_nickname = chat_window.sender_nickname

            print(f"Mensaje recibido de {address}: {mensaje}")
            print(f"sender_nickname {sender_nickname}")
            print(f"recipient_nickname {self.chatroom.sender_nickname}")

            # El mensaje recibido debe mostrarse en la ventana de chat del
            # que recibió (el recipient). Entonces en el chatroom del recipient
            # buscanmos la ventana de chat que tiene abierta con el sender
            self.chatroom.text_box[sender_nickname].append(f"{sender_nickname}: {mensaje}")
        except queue.Empty:
            # Si no hay mensajes en la cola, continuar
            pass
        except Exception as e:
            logger.error(f"Error al procesar mensaje: {e}")

class NicknameWindow(QMainWindow):
    """ Ventana secundaria para ingresar el nickname. """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ingresar Nickname")
        self.setGeometry(200, 200, 300, 150)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.label_instruction = QLabel("Ingresa tu nickname:", self)
        layout.addWidget(self.label_instruction)

        self.txt_nickname = QLineEdit(self)
        layout.addWidget(self.txt_nickname)

        self.btn_confirm = QPushButton("Confirmar", self)
        self.btn_confirm.clicked.connect(self.confirm_nickname)
        layout.addWidget(self.btn_confirm)

    def confirm_nickname(self):
        nickname = self.txt_nickname.text().strip()
        if not nickname:
            QMessageBox.warning(self, "Advertencia", "Por favor, ingresa un nickname.")
            return

        if nickname in USERS:
            QMessageBox.warning(self, "Advertencia", "El nickname ya está en uso.")
            return

        QMessageBox.information(self, "Información", f"Bienvenido {nickname}")
        self.close()

        self.chatroom_windows = ChatroomWindows(nickname)
        self.chatroom_windows.show()
        USERS_CHATROOMS[nickname] = self.chatroom_windows

class MainWindow(QMainWindow):
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
        for nickname, user_info in USERS_CHATROOMS.items():
            for dest_name, config_values in user_info.tcp_clients.items():
                config_values.close()
        for nickname, user_info in USERS_CHATROOMS.items():
            for dest_name, config_values in user_info.tcp_servers.items():
                config_values.terminate()
        for nickname, user_info in USERS.items():
            user_info.chatroom_window.close()
        self.close()

    def ask_nickname_window(self):
        self.nickname_window = NicknameWindow()
        self.nickname_window.show()

    def list_users(self):
        print(USERS)
        for nickname, user_info in USERS.items():
            print(nickname, user_info)
        for nickname, chatroom_window in USERS_CHATROOMS.items():
            print(nickname, chatroom_window)

class UserInfo:
    def __init__(self, nickname: str, chatroom_window: ChatroomWindows):
        self.nickname = nickname
        # El chatroom_window es la ventana principal de la persona
        # aqui puede ver la lista de usuario conectados y abrir ventanas de chat
        # internamente almacena los items a nivel interfaz para poder
        # actualizar la lista de usuarios conectados
        # abrir ventanas de chat y enviar mensajes
        self.chatroom_window = chatroom_window
        self.tcp_clients = {}
        self.tcp_servers = {}
        self.check_incoming_messages_from = {}


def main():
    app = QApplication(sys.argv)
    ventana = MainWindow()
    ventana.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()