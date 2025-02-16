import logging
import sys
import socket
import time
import multiprocessing
import queue
import struct
import os
from typing import Optional, Dict
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout, QListWidget, QListWidgetItem
)

USER_INFO_BY_NICKNAME = {}
MAPPER_ADDR_TO_NICKNAME = {}
USER_CLIENTS_CONNECTED_TO_DIFUSION = {}

LOCAL_IP = "127.0.0.1"
AVAILABLE_PORTS = set(range(20001, 20011))

SERVER_DIFUSION = None
CHECK_DIFUSION = {}
LOCAL_IP_MULTICAST = "224.0.0.0"
LOCAL_PORT_MULTICAST = 30001

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("App principal")

def get_chatroom_by_address(address: str) -> Optional["ChatroomWindows"]:
    """ Retorna la ventana de chat asociada a la dirección IP. """
    nickname = MAPPER_ADDR_TO_NICKNAME.get(address)
    if nickname:
        return USER_INFO_BY_NICKNAME[nickname].chatroom_window

def get_chatroom_by_nickname(nickname: str) -> Optional["ChatroomWindows"]:
    """ Retorna la ventana de chat asociada al nickname. """
    return USER_INFO_BY_NICKNAME.get(nickname).chatroom_window

class MulticastReceiver:
    """
    Clase para recibir mensajes de un grupo multicast específico.
    """

    def __init__(self, multicast_group, port):
        """
        Constructor que configura el socket para unirse al grupo multicast.
        """
        self.multicast_group = multicast_group
        self.ip = multicast_group
        self.port = port

        self.incoming_queue = multiprocessing.Queue()
        self.address = (self.ip, self.port)
        self.stop_event = multiprocessing.Event() # Bandera para detener el proceso
        self.server_thread = multiprocessing.Process(
            target=self.listen_forever,
            args=(self.incoming_queue,
                  self.address,
                  10),
            daemon=True
        )

    def start(self):
        """ Inicia el servidor en un proceso aparte. """
        logger.info("Starting servidor ...")
        self.server_thread.start()

    @staticmethod
    def listen_forever(incoming_queue, address, maximum_connections):
        """
        Escucha indefinidamente los mensajes que lleguen al grupo multicast.
        """
        multicast_group, port = address 
        ttl = 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Después REUSEPORT (no siempre disponible)
        operative_system = os.uname().sysname
        if operative_system != "Windows":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        sock.bind(('', port))

        # Convertir la dirección multicast a formato binario y unirse al grupo
        group_bin = socket.inet_aton(multicast_group)
        mreq = struct.pack('4sL', group_bin, socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        ttl_bin = struct.pack('@i', ttl)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

        print(f"[MulticastReceiver] Escuchando en grupo {multicast_group}:{port} (TTL={ttl}).")

        try:
            while True:
                data, address = sock.recvfrom(1024)
                print(f"[Receptor] Recibido de {address}: {data.decode('utf-8', errors='replace')}")
                msg = data.decode('utf-8', errors='replace')
                incoming_queue.put((msg, address))
        except KeyboardInterrupt:
            print("\n[Receptor] Finalizando recepción...")
        finally:
            sock.close()


class MulticastSender:
    """
    Clase para enviar mensajes a un grupo multicast específico.
    """

    def __init__(self, multicast_group, port, ttl=1):
        """
        Constructor que configura el socket para enviar mensajes multicast.
        :param multicast_group: Dirección IP del grupo multicast (224.0.0.0 a 239.255.255.255)
        :param port: Puerto de destino
        :param ttl: Time-To-Live para limitar alcance (1 => no sale de la red local)
        """
        self.multicast_group = multicast_group
        self.port = port

        # Crear un socket UDP
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Empaquetar el TTL (time-to-live) en un byte y asignarlo al socket
        ttl_bin = struct.pack('b', ttl)
        self.client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

    def send_message(self, message):
        """
        Envía un mensaje al grupo multicast.
        """
        try:
            print(f"[Emisor] Enviando: {message} -> {self.multicast_group}:{self.port}")
            # Se envían los datos en bytes
            self.client_socket.sendto(message.encode('utf-8'), (self.multicast_group, self.port))
        except Exception as e:
            print(f"[Emisor] Error enviando mensaje: {e}")
        # No cerramos el socket todavía, en caso de querer enviar más mensajes

    def close(self):
        """
        Cierra el socket del emisor.
        """
        self.client_socket.close()
        print("[Emisor] Socket cerrado")



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
                 maximum_connections: Optional[int] = 10):
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
        logger.info("Starting servidor ...")
        self.server_thread.start()

    def get_free_port(self):
        if not AVAILABLE_PORTS:
            raise RuntimeError("No hay puertos disponibles")
        return AVAILABLE_PORTS.pop()

    def terminate(self):
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

                    ack = "ACK"
                    conn.send(ack.encode())
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
        print("Enviando mensaje al servidor... {message}")
        self.client_socket.send(message.encode())
        print("Mensaje enviado!")
        data = self.client_socket.recv(self.buffer_size).decode()
        print("Recibido ACK del servidor!")
        print(f"Servidor: {data}")
        return data

    def close(self):
        self.client_socket.close()

class ChatroomWindows(QWidget):
    def __init__(self, nickname: str):
        super().__init__()

        self.sender_nickname = nickname
        self.chat_windows = {} # Diccionario para almacenar las ventanas de chat que tiene abiertas el sender
        self.text_box = {} # Diccionario para almacenar los QTextEdit de cada chat
        self.entry_message = {} # Diccionario para almacenar los QLineEdit de cada chat

        self.setWindowTitle(f"Chatroom de {self.sender_nickname}")
        self.setGeometry(100, 100, 300, 300)
        self.main_layout = QVBoxLayout()

        self.list_users = QListWidget()
        self.list_users.setLayout(QVBoxLayout())

        text_title = QLabel("Usuarios conectados")
        text_title.setFont(QFont("Arial", 18, QFont.Bold))
        text_title.setAlignment(Qt.AlignCenter)
        text_title.setStyleSheet("color: white;")

        self.btn_create_group = QPushButton("Crear grupo", self)
        self.btn_create_group.setFixedSize(150, 40)
        self.btn_create_group.clicked.connect(self.create_window_group)

        # Crear el placeholder como un QListWidgetItem
        placeholder_item = QListWidgetItem("No hay nadie conectado...")
        placeholder_item.setFlags(placeholder_item.flags() & ~Qt.ItemIsEnabled)  # Hacerlo no seleccionable
        placeholder_item.setForeground(Qt.gray)  # Color del texto
        placeholder_item.setFont(QFont("Arial", 10, QFont.StyleItalic))  # Estilo de la fuente
        # Agregar el placeholder al QListWidget
        self.list_users.addItem(placeholder_item)

        # Add widgets to the layout
        self.main_layout.addWidget(text_title)
        self.main_layout.addWidget(self.btn_create_group)
        self.main_layout.addWidget(self.list_users)

        # Establecer el layout principal en la ventana
        self.setLayout(self.main_layout)

        # conectar el usuario al server de difusion
        if self.sender_nickname not in USER_CLIENTS_CONNECTED_TO_DIFUSION:
            client_socket = MulticastSender(
                SERVER_DIFUSION.ip,
                SERVER_DIFUSION.port
                )
            time.sleep(1)
            USER_CLIENTS_CONNECTED_TO_DIFUSION[self.sender_nickname] = client_socket
            MAPPER_ADDR_TO_NICKNAME[client_socket.client_socket.getsockname()] = self.sender_nickname
            CHECK_DIFUSION[nickname] = CheckIncomingMessages(SERVER_DIFUSION, self, "difusion")
            print(USER_CLIENTS_CONNECTED_TO_DIFUSION)
            print(CHECK_DIFUSION)


        self.timer = QTimer()
        self.timer.timeout.connect(self.update_user_list)
        self.timer.start(1000)

    def update_user_list(self):
        """ Actualiza la lista de usuarios conectados. """
        if len(USER_INFO_BY_NICKNAME) <= 1:
            return

        self.list_users.clear()  # Limpiar la lista actual
        for recipient_nickname in USER_INFO_BY_NICKNAME.keys():
            if self.sender_nickname == recipient_nickname:
                continue
            self.list_users.addItem(recipient_nickname)
        self.list_users.itemClicked.connect(self.open_chat_from_list_users)

    def open_chat_from_list_users(self, item):
        recipient_nickname = item.text()
        self.create_window_chat(recipient_nickname, self.sender_nickname)

    def open_chat_in_recipient_side(self, recipient_nickname, sender_nickname = None):
        if sender_nickname is None:
            sender_nickname = self.sender_nickname
        self.create_window_chat(recipient_nickname, sender_nickname)

    def create_window_group(self):
        # Crear una nueva ventana para el chat
        self.group_chat = QMainWindow()
        self.group_chat.setWindowTitle("Group chat")
        self.group_chat.setGeometry(100, 100, 400, 500)

        self.central_widget = QWidget()
        self.group_chat.setCentralWidget(self.central_widget)
        self.group_layout = QVBoxLayout(self.central_widget)

        # Cuadro de texto para mostrar los mensajes del chat
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.group_layout.addWidget(self.chat_display)

        # Cuadro de texto para escribir mensajes
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Escribe tu mensaje aquí...")
        self.group_layout.addWidget(self.chat_input)

        # Botón para enviar mensajes
        send_button = QPushButton('Enviar')
        send_button.clicked.connect(self.send_message)
        self.group_layout.addWidget(send_button)

        self.group_chat.show()

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
        btn_enviar.clicked.connect(lambda: self.send_message_item(recipient_nickname))
        frame_entrada.layout().addWidget(btn_enviar)

        layout.addWidget(frame_entrada)
        self.chat_windows[recipient_nickname].show()

    def send_message(self):
        # Obtener el mensaje del cuadro de texto
        message = self.chat_input.text()
        if message:
            self.chat_input.clear()

            print(self.sender_nickname)
            print(USER_CLIENTS_CONNECTED_TO_DIFUSION)
            client_socket = USER_CLIENTS_CONNECTED_TO_DIFUSION[self.sender_nickname]
            print(client_socket)
            client_socket.send_message(": ".join([self.sender_nickname, message]))


    def send_message_item(self, recipient_nickname: str):
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
                chatroom_recipient = USER_INFO_BY_NICKNAME[recipient_nickname].chatroom_window
                chatroom_recipient.open_chat_in_recipient_side(recipient_nickname=self.sender_nickname,sender_nickname=recipient_nickname)
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
                time.sleep(1)
                sender_user_info.tcp_clients[recipient_nickname] = client_socket
                MAPPER_ADDR_TO_NICKNAME[client_socket.client_socket.getsockname()] = self.sender_nickname

            if self.sender_nickname not in recipient_user_info.tcp_clients: # si el recipient no tiene creado un cliente para escribirle al sender, hay que crearlo
                sender_user_server_for_recipient = sender_user_info.tcp_servers[recipient_nickname]
                client_socket = ClientTCP(f"client_of_{recipient_nickname}_to_send_messages_to_{self.sender_nickname}", sender_user_server_for_recipient.ip, sender_user_server_for_recipient.port)
                time.sleep(1)
                recipient_user_info.tcp_clients[self.sender_nickname] = client_socket

                if chatroom_recipient is not None:
                    MAPPER_ADDR_TO_NICKNAME[client_socket.client_socket.getsockname()] = recipient_nickname

            client_socket = sender_user_info.tcp_clients[recipient_nickname]
            data = client_socket.send_message(message)
            print('Servidor: ' + data)

    def get_font(self, size):
        """ Retorna una fuente con el tamaño especificado. """
        font = self.font()
        font.setPointSize(size)
        return font

class CheckIncomingMessages:
    def __init__(self, server: ServerTCP, chatroom: ChatroomWindows, chat_type: str = "private"):
        self.server = server
        self.chatroom = chatroom
        self.chat_type = chat_type
        self.timer = QTimer(self.chatroom)
        self.timer.timeout.connect(self.check_incoming_messages)
        self.timer.start(100)

    def check_incoming_messages(self):
        try:

            # Intentar obtener un mensaje de la cola

            mensaje, address = self.server.incoming_queue.get_nowait()

            if self.chat_type == "private":
                # Obtener el chatroom de la persona que le envió el mensaje a este self.server
                # esto es para obtener el nickname después
                chat_window = get_chatroom_by_address(address)
                print(chat_window)
                
                # Nickname de la persona que le envió el mensaje a este self.server
                sender_nickname = chat_window.sender_nickname

                print(f"Mensaje recibido de {address}: {mensaje}")
                print(f"sender_nickname {sender_nickname}")
                print(f"recipient_nickname {self.chatroom.sender_nickname}")

                # El mensaje recibido debe mostrarse en la ventana de chat del
                # que recibió (el recipient). Entonces en el chatroom del recipient
                # buscanmos la ventana de chat que tiene abierta con el sender
                self.chatroom.text_box[sender_nickname].append(f"{sender_nickname}: {mensaje}")
            else: # difusion
                print(f" direccion: {address} y Mensaje de multicast {mensaje}")

                for nickname, user_info in USER_INFO_BY_NICKNAME.items():
                    chatroom = user_info.chatroom_window
                    print(chatroom.sender_nickname)
                    print(chatroom.chat_display)
                    chatroom.chat_display.append(f"{address}: {mensaje}")
                    print("llegue aqui")
                    # subir mensajes al chat de difusion del recipient
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
        self.chatroom_windows.update()
        USER_INFO_BY_NICKNAME[nickname] = UserInfo(nickname, self.chatroom_windows)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Ventana Principal")
        self.setGeometry(100, 100, 300, 200)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.btn_nickname = QPushButton("Iniciar sesión", self)
        self.btn_nickname.clicked.connect(self.ask_nickname_window)
        layout.addWidget(self.btn_nickname)

        self.btn_cerrar = QPushButton("Cerrar todas las sesiones", self)
        self.btn_cerrar.clicked.connect(self.close_all)
        layout.addWidget(self.btn_cerrar)

        self.btn_list_users = QPushButton("Debug", self)
        self.btn_list_users.clicked.connect(self.list_users)
        layout.addWidget(self.btn_list_users)

    def close_all(self):
        """ Cierra todos los servidores, clientes y ventanas. """
        for nickname, userinfo in USER_INFO_BY_NICKNAME.items():
            for dest_name, server_socket in userinfo.tcp_servers.items():
                server_socket.terminate()
        for nickname, userinfo in USER_INFO_BY_NICKNAME.items():
            for dest_name, client_socket in userinfo.tcp_clients.items():
                client_socket.close()
        for nickname, userinfo in USER_INFO_BY_NICKNAME.items():
            userinfo.chatroom_window.close()
        self.close()
        #SERVER_DIFUSION.terminate()

    def ask_nickname_window(self):
        self.nickname_window = NicknameWindow()
        self.nickname_window.show()

    def list_users(self):
        for nickname, user_info in USER_INFO_BY_NICKNAME.items():
            print(nickname, user_info)
        for nickname, user_info in USER_INFO_BY_NICKNAME.items():
            print(nickname, user_info.chatroom_window)

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
    global SERVER_DIFUSION
    SERVER_DIFUSION = MulticastReceiver(LOCAL_IP_MULTICAST, LOCAL_PORT_MULTICAST)
    SERVER_DIFUSION.start()
    time.sleep(1)

    app = QApplication(sys.argv)
    ventana = MainWindow()
    ventana.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()