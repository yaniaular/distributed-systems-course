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
    QLabel, QLineEdit, QTextEdit, QHBoxLayout, QListWidget
)

# Diccionario para almacenar los usuarios conectados
USER_INFO_BY_NICKNAME = {}
USERS_CHATROOMS_BY_NICKNAME = {}
USERS_CHATROOMS_BY_ADDR = {}

USERS_CHATDIFUSION_BY_NICKNAME = {}

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
                    logger.info("Mensaje recibido de %s: %s", str(addr), str(msg))

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

class ChatDifusion(QWidget):
    def __init__(self, nickname: str):
        super().__init__()
        self.sender_nickname = nickname

        self.server = ServerTCP(f"main_server", LOCAL_IP)
        self.server.start()
       #self.check_incoming_messages = CheckIncomingMessages(server, self)



        self.setWindowTitle('Chat Grupal')
        self.setGeometry(100, 100, 800, 600)

        # Layout principal (horizontal)
        main_layout = QHBoxLayout()

        # Área de chat (izquierda)
        chat_layout = QVBoxLayout()

        # Cuadro de texto para mostrar los mensajes del chat
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        chat_layout.addWidget(self.chat_display)

        # Cuadro de texto para escribir mensajes
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Escribe tu mensaje aquí...")
        chat_layout.addWidget(self.chat_input)

        # Botón para enviar mensajes
        self.send_button = QPushButton('Enviar')
        self.send_button.clicked.connect(self.send_message)
        chat_layout.addWidget(self.send_button)
        
        self.user_list = QListWidget()
        self.update_user_list()

        # Añadir los layouts al layout principal
        main_layout.addLayout(chat_layout, 75)  # 75% del espacio para el chat
        main_layout.addWidget(self.user_list, 25)  # 25% del espacio para la lista de usuarios

        # Establecer el layout principal en la ventana
        self.setLayout(main_layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_user_list)
        self.timer.start(1000)

    def send_message(self):
        # Obtener el mensaje del cuadro de texto
        message = self.chat_input.text()
        if message:
            # Mostrar el mensaje en el cuadro de chat
            self.chat_display.append(f"Tú: {message}")
            # Limpiar el cuadro de texto
            self.chat_input.clear()
    
    def update_user_list(self):
        """ Actualiza la lista de usuarios conectados. """
        self.user_list.clear()  # Limpiar la lista actual
        for recipient_nickname in USER_INFO_BY_NICKNAME.keys():
            self.user_list.addItem(recipient_nickname)  # Añadir cada usuario de la lista global

    def get_font(self, size):
        """ Retorna una fuente con el tamaño especificado. """
        font = self.font()
        font.setPointSize(size)
        return font

class ChatroomWindows(QWidget):
    def __init__(self, nickname: str):
        super().__init__()


        self.sender_nickname = nickname
        USER_INFO_BY_NICKNAME[self.sender_nickname] = UserInfo(nickname, self)

        self.chat_windows = {} # Diccionario para almacenar las ventanas de chat que tiene abiertas el sender
        self.text_box = {} # Diccionario para almacenar los QTextEdit de cada chat
        self.entry_message = {} # Diccionario para almacenar los QLineEdit de cada chat




        self.setWindowTitle(f"Chatroom de {self.sender_nickname}")
        self.setGeometry(100, 100, 800, 600)

        # Layout principal (horizontal)
        self.main_layout = QHBoxLayout()

        # Área de chat (izquierda)
        self.chat_layout = QVBoxLayout()

        # Cuadro de texto para mostrar los mensajes del chat
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_layout.addWidget(self.chat_display)

        # Cuadro de texto para escribir mensajes
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Escribe tu mensaje aquí...")
        self.chat_layout.addWidget(self.chat_input)

        # Botón para enviar mensajes
        self.send_button = QPushButton('Enviar')
        self.send_button.clicked.connect(self.send_message)
        self.chat_layout.addWidget(self.send_button)
        
        
        self.frame_usuarios = QListWidget()
        self.frame_usuarios.setLayout(QVBoxLayout())

        # Añadir los layouts al layout principal
        self.main_layout.addLayout(self.chat_layout, 75)  # 75% del espacio para el chat
        self.main_layout.addWidget(self.frame_usuarios, 25)  # 25% del espacio para la lista de usuarios

        # Establecer el layout principal en la ventana
        self.setLayout(self.main_layout)



        #lbl_titulo = QLabel(f"Hola {self.sender_nickname}! Usuarios conectados:", self)
        #lbl_titulo.setFont(self.get_font(14))
        #layout.addWidget(lbl_titulo)


        self.timer = QTimer()
        self.timer.timeout.connect(lambda: self.update_user_list())
        self.timer.start(1000)

    def update_user_list(self):
        """ Actualiza la lista de usuarios conectados. """
        self.frame_usuarios.clear()  # Limpiar la lista actual
        for recipient_nickname in USER_INFO_BY_NICKNAME.keys():
            if self.sender_nickname == recipient_nickname:
                continue
            self.frame_usuarios.addItem(recipient_nickname)
        self.frame_usuarios.itemClicked.connect(self.open_chat_item)

    def open_chat_item(self, item, sender_nickname = None):
        recipient_nickname = item.text()
        if sender_nickname is None:
            sender_nickname = self.sender_nickname
        self.create_window_chat(recipient_nickname, sender_nickname)

    def open_chat(self, recipient_nickname, sender_nickname = None):
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

            sender_user_info = USER_INFO_BY_NICKNAME[self.sender_nickname] #yani
            recipient_user_info = USER_INFO_BY_NICKNAME[recipient_nickname] #paco

            chatroom_recipient = None
            if self.sender_nickname not in recipient_user_info.tcp_servers: # si el recipient no tiene un servidor para recibir mensajes del sender, hay que crearlo
                server = ServerTCP(f"server_of_{recipient_nickname}_to_receive_messages_from_{self.sender_nickname}", LOCAL_IP)
                server.start()
                recipient_user_info.tcp_servers[self.sender_nickname] = server
                time.sleep(1)
                chatroom_recipient = USERS_CHATROOMS_BY_NICKNAME[recipient_nickname]
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
    
class CheckIncomingMessagesDifusion:
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

        if nickname in USER_INFO_BY_NICKNAME:
            QMessageBox.warning(self, "Advertencia", "El nickname ya está en uso.")
            return

        QMessageBox.information(self, "Información", f"Bienvenido {nickname}")
        self.close()

        self.chatroom_windows = ChatroomWindows(nickname)
        self.chatroom_windows.show()
        USERS_CHATROOMS_BY_NICKNAME[nickname] = self.chatroom_windows

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.chat_difusion = None
        self.setWindowTitle("Ventana Principal")
        self.setGeometry(100, 100, 300, 200)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.btn_nickname = QPushButton("Conectarte al chatroom", self)
        self.btn_nickname.clicked.connect(self.ask_nickname_window)
        layout.addWidget(self.btn_nickname)

        self.btn_chat_difusion = QPushButton("Crear un chat de difusión", self)
        self.btn_chat_difusion.clicked.connect(self.create_chat_difusion)
        layout.addWidget(self.btn_chat_difusion)

        self.btn_list_users = QPushButton("Revisar usuarios", self)
        self.btn_list_users.clicked.connect(self.list_users)
        layout.addWidget(self.btn_list_users)

        self.btn_cerrar = QPushButton("Cerrar todo", self)
        self.btn_cerrar.clicked.connect(self.close_all)
        layout.addWidget(self.btn_cerrar)

    def create_chat_difusion(self):
        if self.chat_difusion is None:
            self.chat_difusion = ChatDifusion("Chat Grupal")
            self.chat_difusion.show()
        else:
            self.chat_difusion.show()

    def close_all(self):
        """ Cierra todos los servidores, clientes y ventanas. """
        for nickname, chatroom in USERS_CHATROOMS_BY_NICKNAME.items():
            for dest_name, config_values in chatroom.tcp_clients.items():
                config_values.close()
        for nickname, chatroom in USERS_CHATROOMS_BY_NICKNAME.items():
            for dest_name, config_values in chatroom.tcp_servers.items():
                config_values.terminate()
        for nickname, chatroom in USERS_CHATROOMS_BY_NICKNAME.items():
            chatroom.close()
        self.close()

    def ask_nickname_window(self):
        self.nickname_window = NicknameWindow()
        self.nickname_window.show()

    def list_users(self):
        for nickname, user_info in USER_INFO_BY_NICKNAME.items():
            print(nickname, user_info)
        for nickname, chatroom_window in USERS_CHATROOMS_BY_NICKNAME.items():
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