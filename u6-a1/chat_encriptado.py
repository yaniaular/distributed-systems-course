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
from typing import Optional, Dict
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout, QListWidget, QListWidgetItem
)

USER_INFO_BY_NICKNAME = {}
MAPPER_ADDR_TO_NICKNAME = {}

LOCAL_IP = "127.0.0.1"
AVAILABLE_PORTS = set(range(20001, 20011))

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

class ServerTCP:

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
            AVAILABLE_PORTS.add(self.port)  # Devolver el puerto al conjunto

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
        send_button.clicked.connect(self.send_message_group)
        self.group_layout.addWidget(send_button)
        self.group_chat.show()

    def send_message_group(self):
        # TODO: implementar lógica para cada acción
        message = self.chat_input.text()
        if message:
            self.chat_input.clear()
            action = "ACTION"
            MULTICAST_NODE.send(f"{action}:{self.sender_nickname}:{message}")

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
            if self.sender_nickname not in recipient_user_info.tcp_servers: # si el recipient no tiene un servidor tcp para recibir mensajes del sender, hay que crearlo
                # TODO: mandar mensaje al orchestrator para que se cree el servidor del lado del recipient
                server = ServerTCP(f"server_of_{recipient_nickname}_to_receive_messages_from_{self.sender_nickname}", LOCAL_IP)
                server.start()
                recipient_user_info.tcp_servers[self.sender_nickname] = server
                time.sleep(1)
                chatroom_recipient = get_chatroom_by_nickname(recipient_nickname)
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
                # TODO: mandar mensaje al orchestrator para que se cree el cliente del lado del recipient
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
            mensaje, address = self.server.incoming_queue.get_nowait()
            if self.chat_type == "private": # TODO siempre es privado, antes se usaba para difusion
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

        operative_system = os.uname().sysname
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
                    self.check_action(action, sender_nickname, is_master)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[ERROR] {e}")
                break
    
    def check_action(self, action, sender_nickname, is_master):
        # TODO: implementar lógica para procesar mensajes
        pass

def main():
    global MULTICAST_NODE
    # Conectarse a un servidor multicast para comunicación interna o técnica entre nodos.
    # Esto actuará como orquestador de mensajes entre los nodos.
    ip_multicast = "224.0.0.0"
    port_multicast = 30001
    is_master = True if len(sys.argv) > 1 and sys.argv[1] == "master" else False
    MULTICAST_NODE = MulticastNode(ip_multicast, port_multicast)
    IncomingMessageOrchestrator(MULTICAST_NODE, is_master)

    app = QApplication(sys.argv)
    ventana = MainWindow()
    ventana.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()