import logging
import sys
import socket
import time
import multiprocessing
import queue
import struct
import errno
import os
import threading
import platform
from typing import Optional, Dict
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout, QListWidget, QListWidgetItem
)

USER_INFO_BY_NICKNAME = {} # información de los usuarios conectados
MAPPER_ADDR_TO_NICKNAME = {}

AVAILABLE_PORTS = [30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009]

# Para enviar mensajes a todos los nodos conectados al grupo multicast
MULTICAST_NODE = None

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

def get_ip_local():
    """Devuelve la IP local principal (por la que saldrían los paquetes a internet)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Conectamos a un destino público (sin enviar datos)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
    except Exception:
        ip_local = "127.0.0.1"
    finally:
        s.close()
    return ip_local

def get_free_port():
    return AVAILABLE_PORTS.pop(0)

MY_MULTICAST_PORT = None
MY_NICKNAME = None
MY_IP = get_ip_local()

class ServerTCP:

    def __init__(self,
                 name: str,
                 ip: str,
                 port: int,
                 buffer_size: Optional[int] = 1024,
                 maximum_connections: Optional[int] = 10):
        logger.info("Configurando servidor...")
        self.name = name
        self.ip = ip
        self.port = port
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

    @staticmethod
    def server_process(incoming_queue, address, buffer_size, maximum_connections):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(address)
        server_socket.listen(maximum_connections)

        try:
            conn, addr = server_socket.accept()
            logger.info("Conexión establecida con: %s", addr)

            while True:
                data = conn.recv(buffer_size)
                if data:
                    msg = data.decode('utf-8')
                    incoming_queue.put((msg, addr))
                    logger.info("Mensaje recibido de %s: %s", str(addr), str(msg))
                    ack = "ACK"
                    conn.send(ack.encode())
        except KeyboardInterrupt:
            logger.warning("\n[KeyboardInterrupt] Servidor cerrando conexión...")
        except Exception as e:
            logger.error("Ocurrió un error: %s", e)

    def terminate(self):
        if self.server_thread.is_alive():
            logger.info("Terminando servidor...")
            self.stop_event.set()  # Activar la bandera para detener el proceso
            self.server_thread.join(timeout=5)  # Esperar a que el proceso termine
            if self.server_thread.is_alive():
                logger.warning("El proceso no terminó correctamente. Forzando terminación...")
                self.server_thread.terminate()  # Forzar la terminación si no responde
            self.server_thread.join()  # Esperar a que el proceso termine completamente

    def __del__(self):
        self.terminate()

class ClientTCP:
    def __init__(self, name: str, ip: str, port: int, buffer_size: Optional[int] = 1024):
        self.name = name
        self.address = (ip, port)
        self.buffer_size = buffer_size
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)
        logger.info("Conexión establecida con el servidor!")
        self.send_message("Hola, estoy conectado!")

    def send_message(self, message: str):
        print(f"Enviando mensaje al servidor... {message}")
        self.client_socket.send(message.encode())
        data = self.client_socket.recv(self.buffer_size).decode()
        print(f"Recibido ACK del servidor! {data}")
        return data

    def close(self):
        self.client_socket.close()

class ChatroomWindows(QWidget):
    def __init__(self, nickname: str):
        super().__init__()

        self.sender_nickname = nickname

        self.chat_windows = {} # Diccionario para almacenar las ventanas de cada chat privado
        self.text_box = {} # Diccionario para almacenar los QTextEdit de cada chat privado
        self.entry_message = {} # Diccionario para almacenar los QLineEdit de cada chat privado

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

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_user_list)
        self.timer.start(1000)

    def update_user_list(self):
        """ Actualiza la lista de usuarios conectados. """
        if len(USER_INFO_BY_NICKNAME) == 0:
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

        user_info = USER_INFO_BY_NICKNAME.get(recipient_nickname, False)
        if not user_info:
            USER_INFO_BY_NICKNAME[recipient_nickname] = UserInfo(recipient_nickname)
            user_info = USER_INFO_BY_NICKNAME[recipient_nickname]

        # CREAR SERVIDOR PARA RECIBIR MENSAJES DE LA PERSONA CON LA QUE QUIERO CHATEAR
        time.sleep(1)
        if user_info.server_listening is None:
            print(f"creando server para recibir mensajes de {recipient_nickname}")
            # si el sender no tiene un servidor tcp para recibir mensajes del recipient, hay que crearlo
            port = get_free_port()
            server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_messages_from_{recipient_nickname}", get_ip_local(), port)
            server.start()
            time.sleep(1)
            user_info.server_listening = server
            user_info.check_incoming_messages = CheckIncomingMessages(server, self) # mando el chatroom para que pueda actualizar la interfaz

            # si el recipient no tiene un cliente para escribirnos
            # hay que decirle al recipient que cree uno
            self.send_request_to_create_tcp_client(recipient_nickname, port)

               
            #if user_info.client is None:
                # si el recipient no tiene un servidor tcp para recibir mensajes del sender
                # hay que decirle al recipient que cree uno
            #    self.send_request_to_create_tcp_server(recipient_nickname)
            #print(f"{recipient_nickname} necesito que crees un server para que escuches mis mensajes")


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
        send_button.clicked.connect(self.send_message_orchestrator)
        self.group_layout.addWidget(send_button)
        self.group_chat.show()

    def create_window_chat(self, recipient_nickname: str, sender_nickname: Optional[str] = None):
        if sender_nickname is None:
            sender_nickname = self.sender_nickname

        user_info = USER_INFO_BY_NICKNAME.get(recipient_nickname, False)
        if not user_info:
            USER_INFO_BY_NICKNAME[recipient_nickname] = UserInfo(recipient_nickname)
            user_info = USER_INFO_BY_NICKNAME[recipient_nickname]
        
        if recipient_nickname not in self.chat_windows:
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

            user_info.private_chat = self.chat_windows[recipient_nickname]
            user_info.visual_chat = self.text_box[recipient_nickname]
            user_info.entry_message = self.entry_message[recipient_nickname]        

            self.chat_windows[recipient_nickname].show()
            print(f"Chat con {recipient_nickname} creado.")

    def send_message_item(self, recipient_nickname: str):
        """ Envía un mensaje y lo muestra en el área de mensajes. """
        message = self.entry_message[recipient_nickname].text()
        if message.strip():  # Verificar que el mensaje no esté vacío

            # Mostrar el mensaje en el área de mensajes
            self.text_box[recipient_nickname].append(f"Tú: {message}")
            self.entry_message[recipient_nickname].clear()

            recipient_user_info = USER_INFO_BY_NICKNAME[recipient_nickname] #paco

            client_socket = recipient_user_info.client
            data = client_socket.send_message(message)
            print('Servidor: ' + data)

    def send_request_to_create_tcp_server(self, recipient_nickname):
        """ This method send a request to create a tcp server in the recipient side
        """
        action = "CREATE_TCP_SERVER"
        sender = self.sender_nickname
        recipient = recipient_nickname
        message = f"{action}:{sender}:{recipient}"
        self.send_message_orchestrator(message)

    def send_request_to_create_tcp_client(self, recipient_nickname, port):
        """ This method send a request to create a tcp client in the recipient side
        """
        action = "CREATE_TCP_CLIENT"
        sender = self.sender_nickname
        recipient = recipient_nickname
        sender_ip = MY_IP
        sender_port = port
        message = f"{action}:{sender}:{recipient}:{sender_ip}:{sender_port}"
        self.send_message_orchestrator(message)

    def send_request_to_join_chatroom(self):
        action = "JOIN_CHATROOM"
        sender = self.sender_nickname
        message = f"{action}:{sender}"
        self.send_message_orchestrator(message)

    def send_message_to_group(self):
        content = self.chat_input.text()
        if not content:
            return
        self.chat_input.clear()
        action = "SEND_GROUP_MESSAGE"
        sender = self.sender_nickname
        message = f"{action}:{sender}:{content}"
        self.send_message_orchestrator(message)

    def send_my_info_to_new_user(self, recipient_nickname):
        action = "UPDATE_USER_LIST"
        sender = self.sender_nickname
        message = f"{action}:{sender}"
        self.send_message_orchestrator(message)

    def send_message_orchestrator(self, message):
        MULTICAST_NODE.send(message)

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
            mensaje, address = self.server.incoming_queue.get_nowait()


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
            # que recibió (el recipient).
            # TODO: esto debe cambiar a enviar un mensaje al orchestrator
            # ya que ahorita actualiza la interfaz gráfica directamente
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
        global MY_NICKNAME, MY_CHATROOM
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
        MY_CHATROOM = self.chatroom_windows
        MY_NICKNAME = nickname
        MY_CHATROOM.send_request_to_join_chatroom()

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
            if userinfo.server_listening:
                userinfo.server_listening.terminate()
            if userinfo.check_incoming_messages:
                userinfo.check_incoming_messages.timer.stop()
                userinfo.check_incoming_messages.timer.deleteLater()
            if userinfo.client:
                userinfo.client.close()
        self.close()

    def ask_nickname_window(self):
        self.nickname_window = NicknameWindow()
        self.nickname_window.show()

    def list_users(self):
        for nickname, user_info in USER_INFO_BY_NICKNAME.items():
            print(nickname, user_info)
        for nickname, user_info in USER_INFO_BY_NICKNAME.items():
            print(nickname, user_info.chatroom_window)

class UserInfo:
    def __init__(self, nickname: str):
        self.nickname = nickname
        self.server_listening = None # servidor tcp para recibir mensajes de este usuario
        self.check_incoming_messages = None # hilo para revisar mensajes que esten en la cola
        self.client = None # cliente tcp para enviar mensajes a este usuario
        self.private_chat = None # ventana de chat privado con este usuario es de tipo QMainWindow
        self.visual_chat = None # es el area donde se ven los mensajes en la ventana de chat privado con este usuario
        self.entry_message = None # es el area para escribir mis mensajes en la ventana de chat privado con este usuario

class MulticastNode:
    """ Esta clase se encarga de crear un nodo el cual creará una conexión multicast 
    para difundir mensajes a todos los demás nodos conectados al grupo multicast. 
    Los mensajes son almacenados en una cola incoming_messages_queue y deben ser
    procesados por otro hilo.

    IMPORTANTE! Debe implementarse la lógica para procesar los mensajes recibidos y 
    guardados en el atributo incoming_messages_queue.
    """
    def __init__(self, group, port, ttl=1):
        self.group = group # Dirección de grupo multicast
        self.port = port # Puerto multicast
        self.ttl = ttl # Time-to-live (saltos máximos)
        self.sock = None # Socket multicast
        self.incoming_messages_queue = None # Cola de mensajes entrantes
        self.stop_event = None # Evento para detener el hilo de escucha
        self.receiver_thread = None # Hilo de escucha
        self.start() # Iniciar hilo de escucha

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        operative_system = platform.uname().system
        if operative_system != "Windows":
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        self.sock.bind(('', self.port))

        group_bin = socket.inet_aton(self.group)
        mreq = struct.pack('4sL', group_bin, socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        ttl_bin = struct.pack('@i', self.ttl)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

        print(f"[MulticastReceiver] Escuchando en grupo {self.group}:{self.port} (TTL={self.ttl}).")

        self.incoming_messages_queue = multiprocessing.Queue()
        self.stop_event = multiprocessing.Event()
        self.receiver_thread = multiprocessing.Process(
            target=self.receiver,
            args=(self.sock,self.incoming_messages_queue, self.group, self.port, self.stop_event),
            daemon=True
        )
        self.receiver_thread.start()

    def stop(self):
        print("[MulticastReceiver] Deteniendo receptor...")
        self.stop_event.set()
        self.receiver_thread.terminate()
        self.receiver_thread.join()
        
    @staticmethod
    def receiver(sock, queue, group, port, stop_event):
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(1024)
                msg = data.decode('utf-8', errors='replace')
                queue.put((msg, addr))
            except socket.timeout:
                pass
            except OSError as e:
                # Verificar si es 'Resource temporarily unavailable'
                if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                    # Podemos ignorar este error y seguir esperando
                    continue
                else:
                    # Si es otro error, lo mostramos o lo manejamos
                    print("[RECEIVER] Error recibiendo:", e)
                    break
            except Exception as e:
                print("[RECEIVER] Error recibiendo:", e)
                break
        sock.close()
        print("[MulticastReceiver] Finalizando proceso de escucha.")

    def send(self, msg):
        try:
            data = msg.encode('utf-8')
            self.sock.sendto(data, (self.group, self.port))
            print(f"[ENVIADO] {msg}")
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
        except Exception as e:
            print(f"[ERROR] {e}")

class IncomingMessageOrchestrator:
    """ Esta clase crea un hilo que se enacarga de procesar los mensajes
    entrantes en el atributo incoming_messages_queue de un nodo multicast.
    """
    def __init__(self, node: MulticastNode, is_master: bool):
        process_incoming_thread = threading.Thread(
            target=self.process,
            args=(node, is_master),
            daemon=True
        )
        process_incoming_thread.start()

    def process(self, node, is_master):
        while True:
            try:
                msg, addr = node.incoming_messages_queue.get()
                if msg:
                    arguments = msg.split(":")
                    action = arguments[0]
                    sender_nickname = arguments[1]
                    self.check_action(action, sender_nickname, arguments[2:], is_master)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[ERROR] {e}")
                break
    
    def check_action(self, action, sender_nickname, arguments, is_master):
        global MY_NICKNAME, USER_INFO_BY_NICKNAME, MY_CHATROOM
        print(f"[Recibido en {MY_NICKNAME}] {action} de {sender_nickname}")

        if action == "CREATE_TCP_SERVER":
            recipient_nickname = arguments[0]
            if recipient_nickname == MY_NICKNAME:
                user_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
                if not user_info:
                    USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                    user_info = USER_INFO_BY_NICKNAME[sender_nickname]
                MY_CHATROOM.open_chat_in_recipient_side(recipient_nickname=sender_nickname, sender_nickname=recipient_nickname)
            return

        if action == "CREATE_TCP_CLIENT":
            recipient_nickname = arguments[0]
            if recipient_nickname == MY_NICKNAME:
                sender_ip = arguments[1]
                sender_port = int(arguments[2])
                user_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
                if not user_info:
                    USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                    user_info = USER_INFO_BY_NICKNAME[sender_nickname]
                if user_info.client is None: # tengo un cliente para escribirle a sender???
                    print(f"Intentanto crear cliente para enviar mensajes a {sender_nickname} - {sender_ip}:{sender_port}")
                    client_socket = ClientTCP(f"client_of_{recipient_nickname}_to_send_messages_to_{sender_nickname}", sender_ip, sender_port)
                    user_info.client = client_socket # lo usaremos para enviar mensajes al sender
            return

        if action == "JOIN_CHATROOM":
            if MY_NICKNAME != sender_nickname:
                USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                MY_CHATROOM.update_user_list()
                MY_CHATROOM.send_my_info_to_new_user(MY_NICKNAME)
            return
        
        if action == "UPDATE_USER_LIST":

            if sender_nickname != MY_NICKNAME and sender_nickname not in USER_INFO_BY_NICKNAME:
                USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                MY_CHATROOM.update_user_list()
            return

def main():
    global MULTICAST_NODE, MY_MULTICAST_PORT
    # Conectarse a un servidor multicast para comunicación interna o técnica entre nodos.
    # Esto actuará como orquestador de mensajes entre los nodos.
    ip_multicast = "224.0.0.0"
    is_master = True if len(sys.argv) > 1 and sys.argv[1] == "master" else False
    MY_MULTICAST_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30001
    MULTICAST_NODE = MulticastNode(ip_multicast, MY_MULTICAST_PORT)
    IncomingMessageOrchestrator(MULTICAST_NODE, is_master)

    app = QApplication(sys.argv)
    ventana = MainWindow()
    ventana.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()