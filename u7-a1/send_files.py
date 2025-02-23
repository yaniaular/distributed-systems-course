import logging
import os
import sys
import socket
import time
import multiprocessing
import queue
import struct
import errno
import signal
import platform
from typing import Optional, Dict
from PyQt5.QtCore import QTimer, Qt, QObject, pyqtSignal, QThread
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout, QListWidget, QListWidgetItem
)

USER_INFO_BY_NICKNAME = {} # información de los usuarios conectados
MAPPER_ADDR_TO_NICKNAME = {}

AVAILABLE_PORTS_MASTER = [30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009]
AVAILABLE_PORTS_SLAVE = [40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009]
IS_MASTER = False

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("App principal")

usuarios = {"yani": 12345, "paco": 12345}

def caesar_encrypt(message: str, shift: int) -> str:
    result = ""
    for char in message:
        # Encriptamos letras mayúsculas
        if char.isupper():
            result += chr((ord(char) - 65 + shift) % 26 + 65)
        # Encriptamos letras minúsculas
        elif char.islower():
            result += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            # Si no es letra, se mantiene igual
            result += char
    return result

def caesar_decrypt(message: str, shift: int) -> str:
    # La desencriptación es simplemente encriptar con el negativo del shift
    return caesar_encrypt(message, -shift)

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
    if IS_MASTER:
        port = AVAILABLE_PORTS_MASTER.pop(0)
        logger.info("Usando puerto maestro %s", port)
        return port
    port = AVAILABLE_PORTS_SLAVE.pop(0)
    logger.info("Usando puerto esclavo %s", port)
    return port

THREAD_ORCHESTRATOR = None
WORKER_ORCHESTRATOR = None
MY_MULTICAST_PORT = None
MY_NICKNAME = None
MY_CHATROOM = None
MY_IP = get_ip_local()
SHIFT = 30

def terminate_application():
    """
    Manejador de señales para Ctrl + C (SIGINT) o SIGTERM.
    Cierra el programa.
    """
    global MY_CHATROOM, USER_INFO_BY_NICKNAME, WORKER_ORCHESTRATOR, THREAD_ORCHESTRATOR
    logger.debug("[SALIR] Saliendo de la aplicación...")
    logger.debug("MY_CHATROOM %s", MY_CHATROOM)

    if MY_CHATROOM:
        for worker in MY_CHATROOM.check_workers.values():
            worker.stop()
            #worker.quit()
        for thread in MY_CHATROOM.check_threads.values():
            thread.quit()
        MY_CHATROOM.close()
    for user_info in USER_INFO_BY_NICKNAME.values():
        if user_info.server_listening:
            user_info.server_listening.terminate()
        if user_info.client:
            user_info.client.close()
        if user_info.private_chat:
            user_info.private_chat.close()
        if user_info.check_incoming_messages:
            user_info.check_incoming_messages.stop()
            user_info.check_incoming_messages.quit()
    if WORKER_ORCHESTRATOR:
        WORKER_ORCHESTRATOR.stop()
    if THREAD_ORCHESTRATOR.isRunning():
        THREAD_ORCHESTRATOR.quit()
    sys.exit(0)

def singal_handler_terminate(signum, frame):
    logger.debug("Señal de terminación recibida %s", signum)
    terminate_application()

#signal.signal(signal.SIGINT, singal_handler_terminate)
#signal.signal(signal.SIGTERM, singal_handler_terminate)

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
        logger.info("[%s]: Usando IP: %s - Usando puerto: %s", self.name, self.ip, self.port)
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
                    decrypted_msg = caesar_decrypt(msg, SHIFT)
                    incoming_queue.put((decrypted_msg, addr))
                    logger.info("Mensaje recibido de %s: %s", str(addr), str(decrypted_msg))
                    ack = "ACK"
                    ack_encrypted = caesar_encrypt(ack, SHIFT)
                    conn.send(ack_encrypted.encode())
        except KeyboardInterrupt:
            logger.warning("\n[KeyboardInterrupt] Servidor cerrando conexión...")
        except Exception as e:
            logger.error("Ocurrió un error: %s", e)

    def terminate(self):
        if self.server_thread.is_alive():
            logger.info("Terminando servidor...")
            self.stop_event.set()  # Activar la bandera para detener el proceso
            self.server_thread.terminate()  # Forzar la terminación si no responde
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

    def send_message(self, message: str):
        encrypted_message = caesar_encrypt(message, SHIFT)
        self.client_socket.send(encrypted_message.encode())
        data = self.client_socket.recv(self.buffer_size).decode()
        decrypted_data = caesar_decrypt(data, SHIFT)
        if decrypted_data == "ACK":
            logger.info("Mensaje enviado correctamente.")
        return decrypted_data

    def close(self):
        self.client_socket.close()

class ChatroomWindows(QWidget):
    def __init__(self, nickname: str):
        super().__init__()
        self.sender_nickname = nickname

        self.chat_windows = {} # Diccionario para almacenar las ventanas de cada chat privado
        self.text_box = {} # Diccionario para almacenar los QTextEdit de cada chat privado
        self.entry_message = {} # Diccionario para almacenar los QLineEdit de cada chat privado
        self.check_workers = {} # Diccionario para almacenar los workers de cada chat privado
        self.check_threads = {} # Diccionario para almacenar los threads de cada chat privado

        self.setWindowTitle(f"Chatroom de {self.sender_nickname}")
        self.setGeometry(100, 100, 300, 300)
        self.main_layout = QVBoxLayout()

        self.list_users = QListWidget()
        self.list_users.setLayout(QVBoxLayout())

        text_title = QLabel("Usuarios conectados")
        text_title.setFont(QFont("Arial", 18, QFont.Bold))
        text_title.setAlignment(Qt.AlignCenter)
        text_title.setStyleSheet("color: gray;")

        self.btn_create_group = QPushButton("Crear grupo", self)
        self.btn_create_group.setFixedSize(150, 40)
        self.btn_create_group.clicked.connect(self.create_window_group)

        placeholder_item = QListWidgetItem("No hay nadie conectado...") # Crear el placeholder como un QListWidgetItem
        placeholder_item.setFlags(placeholder_item.flags() & ~Qt.ItemIsEnabled)  # Hacerlo no seleccionable
        placeholder_item.setForeground(Qt.gray)
        placeholder_item.setFont(QFont("Arial", 10, QFont.StyleItalic))
        self.list_users.addItem(placeholder_item) # Agregar el placeholder al QListWidget

        # Add widgets to the layout
        self.main_layout.addWidget(text_title)
        self.main_layout.addWidget(self.btn_create_group)
        self.main_layout.addWidget(self.list_users)

        # Establecer el layout principal en la ventana
        self.setLayout(self.main_layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_user_list)
        self.timer.start(1000)

    def update_private_chat(self, mensaje):
        # Aquí actualizamos la interfaz de forma segura en el hilo principal
        # Asegúrate de usar la clave correcta, por ejemplo, el nickname del destinatario
        sender_nickname, mensaje = mensaje.split(":")
        logger.debug("Mensaje recibido de %s: %s", sender_nickname, mensaje)
        if sender_nickname in self.text_box:
            self.text_box[sender_nickname].append(f"{sender_nickname}: {mensaje}")
        else:
            logger.error("No se encontró la clave en text_box")

    def update_user_list(self):
        """ Actualiza la lista de usuarios conectados. """
        if len(USER_INFO_BY_NICKNAME) == 0:
            return
        self.list_users.clear()  # Limpiar la lista actual de la interfaz
        for recipient_nickname in USER_INFO_BY_NICKNAME.keys():
            if self.sender_nickname == recipient_nickname:
                continue
            self.list_users.addItem(recipient_nickname)
        self.list_users.itemClicked.connect(self.open_chat_from_list_users) # abrir chat privado al hacer clic

    def open_chat_from_list_users(self, item):
        recipient_nickname = item.text()
        self.create_private_window_chat(recipient_nickname, self.sender_nickname)

        user_info = USER_INFO_BY_NICKNAME.get(recipient_nickname, False)
        if not user_info:
            USER_INFO_BY_NICKNAME[recipient_nickname] = UserInfo(recipient_nickname)
            user_info = USER_INFO_BY_NICKNAME[recipient_nickname]

        # crear servidor para recibir mensajes de la persona con la que quiero chatear
        if user_info.server_listening is None:
            # si el sender no tiene un servidor tcp para recibir mensajes del recipient, hay que crearlo
            logger.debug("creando server para recibir mensajes de %s", recipient_nickname)
            port = get_free_port()
            server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_messages_from_{recipient_nickname}", get_ip_local(), port)
            server.start()
            user_info.server_listening = server

            # crear worker para procesar mensajes entrantes y actualizar la GUI
            # esto se hizo porque con hilos normales la interfaz se congelaba
            self.check_workers[recipient_nickname] = CheckPrivateIncomingMessagesWorker(server, recipient_nickname)
            self.check_threads[recipient_nickname] = QThread()
            self.check_workers[recipient_nickname].moveToThread(self.check_threads[recipient_nickname])
            self.check_workers[recipient_nickname].messageReceived.connect(self.update_private_chat)
            self.check_threads[recipient_nickname].started.connect(self.check_workers[recipient_nickname].process)
            self.check_threads[recipient_nickname].start()

            # esperar un segundo para que el server se inicie
            time.sleep(1)

            # si el recipient no tiene un cliente para escribirnos hay
            # que enviarle una solicitud al recipient para que cree uno
            self.send_request_to_create_tcp_client(recipient_nickname, port)
               
            # si el recipient no tiene un servidor tcp para recibir mensajes
            # de este sender, hay que enviarle una solicitud al recipient
            # para que cree uno
            if user_info.client is None:
                self.send_request_to_create_tcp_server(recipient_nickname)

    def open_chat_in_recipient_side(self, recipient_nickname, sender_nickname = None):
        if sender_nickname is None:
            sender_nickname = self.sender_nickname
        self.create_private_window_chat(recipient_nickname, sender_nickname)

        user_info = USER_INFO_BY_NICKNAME.get(recipient_nickname, False)
        if not user_info:
            USER_INFO_BY_NICKNAME[recipient_nickname] = UserInfo(recipient_nickname)
            user_info = USER_INFO_BY_NICKNAME[recipient_nickname]

        # crear servidor para recibir mensajes de la persona con la que quiero chatear
        if user_info.server_listening is None:
            # si el sender no tiene un servidor tcp para recibir mensajes del recipient, hay que crearlo
            logger.debug("creando server para recibir mensajes de %s", recipient_nickname)
            port = get_free_port()
            server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_messages_from_{recipient_nickname}", get_ip_local(), port)
            server.start()
            user_info.server_listening = server

            # crear worker para procesar mensajes entrantes y actualizar la GUI
            self.check_workers[recipient_nickname] = CheckPrivateIncomingMessagesWorker(server, recipient_nickname)
            self.check_threads[recipient_nickname] = QThread()
            self.check_workers[recipient_nickname].moveToThread(self.check_threads[recipient_nickname])
            self.check_workers[recipient_nickname].messageReceived.connect(self.update_private_chat)
            self.check_threads[recipient_nickname].started.connect(self.check_workers[recipient_nickname].process)
            self.check_threads[recipient_nickname].start()

            # esperar un segundo para que el server se inicie
            time.sleep(1)

            # si el recipient no tiene un cliente para escribirnos hay
            # que enviarle una solicitud al recipient para que cree uno
            self.send_request_to_create_tcp_client(recipient_nickname, port)

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
        send_button.clicked.connect(lambda: self.send_message_orchestrator(self.chat_input.text()))
        self.group_layout.addWidget(send_button)
        self.group_chat.show()

    def create_private_window_chat(self, recipient_nickname: str, sender_nickname: Optional[str] = None):
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
            btn_enviar.clicked.connect(lambda: self.send_private_message(recipient_nickname))
            frame_entrada.layout().addWidget(btn_enviar)

            layout.addWidget(frame_entrada)

            user_info.private_chat = self.chat_windows[recipient_nickname]
            user_info.visual_chat = self.text_box[recipient_nickname]
            user_info.entry_message = self.entry_message[recipient_nickname]

            self.chat_windows[recipient_nickname].show()
            logger.debug("Chat con %s creado.", recipient_nickname)

    def send_private_message(self, recipient_nickname: str):
        """ Envía un mensaje y lo muestra en el área de mensajes. """
        message = self.entry_message[recipient_nickname].text()
        if message.strip():  # Verificar que el mensaje no esté vacío

            # Mostrar el mensaje en el área de mensajes
            self.text_box[recipient_nickname].append(f"Tú: {message}")
            self.entry_message[recipient_nickname].clear()

            for nickname, user_info in USER_INFO_BY_NICKNAME.items():
                logger.debug("nickname %s", nickname)
                logger.debug("user_info.client %s", user_info.client)
                logger.debug("user_info.server_listening %s", user_info.server_listening)
                logger.debug("user_info.check_incoming_messages %s", user_info.check_incoming_messages)
                logger.debug("user_info.private_chat %s", user_info.private_chat)
                logger.debug("user_info.visual_chat %s", user_info.visual_chat)
                logger.debug("user_info.entry_message %s", user_info.entry_message)

            logger.debug("Enviando mensaje a %s: %s", recipient_nickname, message)
            recipient_user_info = USER_INFO_BY_NICKNAME[recipient_nickname]
            client_socket = recipient_user_info.client
            data = client_socket.send_message(message)
            logger.debug("Servidor: %s", data)

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

    def send_my_info_to_new_user(self):
        action = "UPDATE_USER_LIST"
        sender = self.sender_nickname
        message = f"{action}:{sender}"
        self.send_message_orchestrator(message)

    def send_message_orchestrator(self, message):
        logger.info("Enviando mensaje: %s", message)
        WORKER_ORCHESTRATOR.send(message)

    def get_font(self, size):
        """ Retorna una fuente con el tamaño especificado. """
        font = self.font()
        font.setPointSize(size)
        return font

class CheckPrivateIncomingMessagesWorker(QObject):
    messageReceived = pyqtSignal(str)  # Emitirá el mensaje recibido

    def __init__(self, server, sender_nickname):
        super().__init__()
        self.server = server
        self.sender_nickname = sender_nickname
        self.running = True
        logger.info("************ Worker creado para %s", sender_nickname)

    def process(self):
        while self.running:
            try:
                mensaje, address = self.server.incoming_queue.get(timeout=0.1) # TODO: guardar el address
                logger.debug("Mensaje recibido en worker: %s", mensaje)
                # Emitir el mensaje recibido para actualizar la GUI en el hilo principal
                self.messageReceived.emit(f"{self.sender_nickname}:{mensaje}")
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error en worker: {e}")
                break

    def stop(self):
        self.running = False

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

        self.label_instruction_password = QLabel("Ingresa tu contraseña:", self)
        layout.addWidget(self.label_instruction_password)

        self.txt_password = QLineEdit(self)
        layout.addWidget(self.txt_password)

        self.btn_confirm = QPushButton("Confirmar", self)
        self.btn_confirm.clicked.connect(self.confirm_nickname)
        layout.addWidget(self.btn_confirm)

        self.chatroom_windows = None

    def confirm_nickname(self):
        global MY_NICKNAME, MY_CHATROOM
        nickname = self.txt_nickname.text().strip()
        password = self.txt_password.text().strip()
        if not nickname:
            QMessageBox.warning(self, "Advertencia", "Por favor, ingresa un nickname.")
            return

        if nickname in USER_INFO_BY_NICKNAME:
            QMessageBox.warning(self, "Advertencia", "El nickname ya está en uso.")
            return

        if nickname not in usuarios:
            QMessageBox.warning(self, "Advertencia", "Nickname no válido.")
            return
        
        if password != str(usuarios[nickname]):
            QMessageBox.warning(self, "Advertencia", "Contraseña incorrecta.")
            return

        QMessageBox.information(self, "Información", f"Bienvenido {nickname}")

        self.chatroom_windows = ChatroomWindows(nickname) # se usa self porque sino no funciona la interfaz
        self.chatroom_windows.show()
        self.chatroom_windows.update()
        MY_CHATROOM = self.chatroom_windows
        logger.debug("Chatroom creado para %s - %s", nickname, MY_CHATROOM)
        MY_NICKNAME = nickname
        MY_CHATROOM.send_request_to_join_chatroom()
        self.close()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ventana Principal")
        self.setGeometry(100, 100, 300, 200)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.btn_nickname = QPushButton("Iniciar sesión", self)
        self.nickname_window = NicknameWindow()
        self.btn_nickname.clicked.connect(self.ask_nickname_window)
        layout.addWidget(self.btn_nickname)

        self.btn_cerrar = QPushButton("Cerrar todas las sesiones", self)
        self.btn_cerrar.clicked.connect(terminate_application)

        layout.addWidget(self.btn_cerrar)

        self.btn_list_users = QPushButton("Debug", self)
        self.btn_list_users.clicked.connect(self.list_users)
        layout.addWidget(self.btn_list_users)

    def ask_nickname_window(self):
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

class IncomingMessageOrchestrator(QObject):
    """ Esta clase crea un hilo que se enacarga de procesar los mensajes
    entrantes en el atributo incoming_messages_queue de un nodo multicast.
    """
    messageReceived = pyqtSignal(str, str, list, bool)
    
    def __init__(self, is_master, ip_multicast, port):
        super().__init__()
        self.port = port
        self.group = ip_multicast
        self.ttl = 4
        self.create_socket()
        self.is_master = is_master
        self.running = True
        logger.info("IncomingMessageOrchestrator creado.")

    def create_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        operating_system = platform.system()
        logger.debug("Sistema operativo: %s", operating_system)
        if operating_system != "Windows":
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind(('', self.port))
        group_bin = socket.inet_aton(self.group)
        mreq = struct.pack('4sL', group_bin, socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        ttl_bin = struct.pack('@i', self.ttl)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        logger.debug("[MulticastReceiver] Escuchando en grupo %s:%s (TTL=%s).", self.group, self.port, self.ttl)

    def send(self, msg):
        try:
            data = msg.encode('utf-8')
            self.sock.sendto(data, (self.group, self.port))
            logger.debug("[ENVIADO] %s", msg)
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
        except Exception as e:
            logger.error("[ERROR] %s", e)

    def process(self):
        logger.debug("[MulticastReceiver] Iniciando proceso de escucha...")
        while self.running:
            try:
                logger.debug("[MulticastReceiver] Esperando mensaje...")
                data, addr = self.sock.recvfrom(1024)
                msg = data.decode('utf-8', errors='replace')
                logger.info("Recibido en IncomingMessageOrchestrator, msg: %s, addr: %s", msg, addr)
                if msg:
                    arguments = msg.split(":")
                    action = arguments[0]
                    sender_nickname = arguments[1]
                    # Emitir la señal para que el hilo principal maneje la actualización de la GUI
                    self.messageReceived.emit(action, sender_nickname, arguments[2:], self.is_master)
            except socket.timeout:
                pass
            except OSError as e:
                # Verificar si es 'Resource temporarily unavailable'
                if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                    # Podemos ignorar este error y seguir esperando
                    continue
                else:
                    # Si es otro error, lo mostramos o lo manejamos
                    logger.debug("[RECEIVER] Error recibiendo: %s", e)
                    break
            except Exception as e:
                logger.debug("[RECEIVER] Error recibiendo: %s", e)
                break
        self.sock.close()
        logger.debug("[MulticastReceiver] Finalizando proceso de escucha.")

    def stop(self):
        self.running = False

def handle_incoming_message(action, sender_nickname, arguments, is_master):
    global MY_NICKNAME, USER_INFO_BY_NICKNAME, MY_CHATROOM
    
    logger.debug("[Recibido en %s] %s de %s", MY_NICKNAME, action, sender_nickname)

    # Aquí se debe realizar la actualización de la GUI (en el hilo principal)
    if action == "CREATE_TCP_SERVER":
        recipient_nickname = arguments[0]
        if recipient_nickname == MY_NICKNAME:
            user_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
            if not user_info:
                USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                user_info = USER_INFO_BY_NICKNAME[sender_nickname]
            # NOTA: se llama al método desde el hilo principal, ya que este slot se ejecuta en el main thread.
            MY_CHATROOM.open_chat_in_recipient_side(recipient_nickname=sender_nickname, sender_nickname=recipient_nickname)
    elif action == "CREATE_TCP_CLIENT":
        recipient_nickname = arguments[0]
        if recipient_nickname == MY_NICKNAME:
            sender_ip = arguments[1]
            sender_port = int(arguments[2])
            user_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
            if not user_info:
                USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                user_info = USER_INFO_BY_NICKNAME[sender_nickname]
            if user_info.client is None:
                print(f"Intentando crear cliente para enviar mensajes a {sender_nickname} - {sender_ip}:{sender_port}")
                client_socket = ClientTCP(f"client_of_{recipient_nickname}_to_send_messages_to_{sender_nickname}", sender_ip, sender_port)
                user_info.client = client_socket
    elif action == "JOIN_CHATROOM":
        if MY_NICKNAME != sender_nickname:
            USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
            MY_CHATROOM.update_user_list()
            MY_CHATROOM.send_my_info_to_new_user()
    elif action == "UPDATE_USER_LIST":
        if sender_nickname != MY_NICKNAME and sender_nickname not in USER_INFO_BY_NICKNAME:
            USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
            MY_CHATROOM.update_user_list()

def main():
    # python send_files.py <server_type> <multicast_port>
    # Master: python3 send_files.py master 30001
    # Other: python3 send_files.py 30001

    global MY_MULTICAST_PORT, WORKER_ORCHESTRATOR, THREAD_ORCHESTRATOR, MY_CHATROOM, IS_MASTER
    # Conectarse a un servidor multicast para comunicación interna o técnica entre nodos.
    # Esto actuará como orquestador de mensajes entre los nodos.
    ip_multicast = "224.0.0.0"
    is_master = True if len(sys.argv) > 1 and sys.argv[1] == "master" else False
    IS_MASTER = is_master
    MY_MULTICAST_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30000

    logger.debug("ip_multicast %s", ip_multicast)
    logger.debug("is_master %s", is_master)
    logger.debug("MY_MULTICAST_PORT %s", MY_MULTICAST_PORT)

    WORKER_ORCHESTRATOR = IncomingMessageOrchestrator(is_master, ip_multicast, MY_MULTICAST_PORT)
    logger.debug("Create QThread for IncomingMessageOrchestrator")
    THREAD_ORCHESTRATOR = QThread()
    logger.debug("Move IncomingMessageOrchestrator to QThread")
    WORKER_ORCHESTRATOR.moveToThread(THREAD_ORCHESTRATOR)
    # Conectar la señal del worker a un slot que se encargue de actualizar la GUI
    WORKER_ORCHESTRATOR.messageReceived.connect(handle_incoming_message)
    THREAD_ORCHESTRATOR.started.connect(WORKER_ORCHESTRATOR.process)
    THREAD_ORCHESTRATOR.start()

    app = QApplication(sys.argv)
    logger.debug("Creando ventana principal...")
    ventana = MainWindow()
    ventana.show()

    # AQUÍ haces el bucle principal; la ventana se ve
    ret = app.exec_()

    # CUANDO se cierra la ventana, app.exec_() regresa:
    #WORKER_ORCHESTRATOR.stop()
    #THREAD_ORCHESTRATOR.quit()
    #THREAD_ORCHESTRATOR.wait()

    sys.exit(ret)

if __name__ == "__main__":
    main()