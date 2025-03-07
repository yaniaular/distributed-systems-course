import logging
import os
import io
import sys
import socket
import time
import multiprocessing
import tempfile
import queue
import struct
import errno
import shutil
import platform
import stat
from PIL import Image
from player import Player  # Importa la clase Player desde tu archivo
from typing import Optional, Dict
from PyQt5.QtCore import QTimer, Qt, QObject, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLabel, QLineEdit, QTextEdit, QHBoxLayout, QListWidget, QListWidgetItem, QFileDialog, QProgressBar
)

USER_INFO_BY_NICKNAME = {} # información de los usuarios conectados
MAPPER_ADDR_TO_NICKNAME = {}

AVAILABLE_PORTS_MASTER = [30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009]
AVAILABLE_PORTS_SLAVE_1 = [40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009]
AVAILABLE_PORTS_SLAVE_2 = [50000, 50001, 50002, 50003, 50005, 50005, 50006, 50007, 50008, 50009]

IS_MASTER = False
SLAVE_NUMBER = None

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("App principal")

usuarios = {"yani": 12345, "paco": 12345, "blue": 12345}

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
    logger.debug("Getting IP local: %s", ip_local)
    return ip_local

def get_free_port():
    if IS_MASTER:
        port = AVAILABLE_PORTS_MASTER.pop(0)
        logger.info("Tomando un puerto para el nodo maestro %s", port)
        return port
    if SLAVE_NUMBER == "slave1":
        port = AVAILABLE_PORTS_SLAVE_1.pop(0)
        logger.info("Tomando un puerto para el nodo slave 1: %s", port)
        return port
    elif SLAVE_NUMBER == "slave2":
        port = AVAILABLE_PORTS_SLAVE_2.pop(0)
        logger.info("Tomando un puerto para el nodo slave 2: %s", port)
        return port
    return None

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
    if WORKER_ORCHESTRATOR:
        WORKER_ORCHESTRATOR.stop()
    if THREAD_ORCHESTRATOR.isRunning():
        THREAD_ORCHESTRATOR.quit()
    if MY_CHATROOM.group_chat is not None:
        MY_CHATROOM.group_chat.close()
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
                 type_of_data_to_receive: str = "TEXT",
                 buffer_size: Optional[int] = 1024,
                 maximum_connections: Optional[int] = 10):
        logger.debug("Configurando servidor en __init__ ...")
        self.name = name
        self.ip = ip
        self.port = port
        self.incoming_queue = multiprocessing.Queue()
        self.address = (self.ip, self.port)
        logger.debug("[%s]: Usando IP: %s - Usando puerto: %s - En resumen address: %s", self.name, self.ip, self.port, str(self.address))
        self.buffer_size = buffer_size
        self.maximum_connections = maximum_connections
        self.type_of_data_to_receive = type_of_data_to_receive
        self.stop_event = multiprocessing.Event() # Bandera para detener el proceso
        self.server_thread = multiprocessing.Process(
            target=self.server_process,
            args=(self.incoming_queue,
                  self.address,
                  self.type_of_data_to_receive,
                  self.buffer_size,
                  self.maximum_connections,
                  ),
            daemon=True
        )

    def start(self):
        logger.info("Starting servidor ...")
        self.server_thread.start()

    @staticmethod
    def server_process(incoming_queue, address, type_of_data_to_receive, buffer_size, maximum_connections):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(address)
        server_socket.listen(maximum_connections)

        try:
            # El puerto en addr es un puerto efímero asignado 
            # por el sistema operativo del cliente.
            conn, addr = server_socket.accept() # TODO este addr no se usa, se puede borrar
            logger.info("Conexión establecida con: %s", addr)

            while True:
                data = conn.recv(buffer_size)
                if data:
                    if type_of_data_to_receive == "TEXT":
                        msg = data.decode('utf-8')
                        decrypted_msg = caesar_decrypt(msg, SHIFT)
                        incoming_queue.put((decrypted_msg, addr))
                        logger.info("Mensaje recibido de %s: %s", str(addr), str(decrypted_msg))
                        logger.debug("Enviando ACK de mensaje de texto a %s...", str(addr))
                        ack = "ACK"
                        ack_encrypted = caesar_encrypt(ack, SHIFT)
                        conn.sendall(ack_encrypted.encode('utf-8'))
                    else:
                        # logger.debug("Recibido fragmento en server_process")
                        # time.sleep(0.005)
                        incoming_queue.put((data, addr))
                        # TODO tal vez mandar este ACK en el worker
                        # logger.debug("Enviando ACK de fragmento a %s...", str(addr))
                        ack = "ACK"
                        ack_encrypted = caesar_encrypt(ack, SHIFT)
                        conn.sendall(ack_encrypted.encode('utf-8'))
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
        logger.debug("Conexión establecida con el servidor de address %s! ya podemos mandar cosos a esa direccion", self.address)

    def receive_ack(self, timeout=2):
        self.client_socket.settimeout(timeout)
        try:
            ack = self.client_socket.recv(1024)  # Recibir datos del socket
            if ack == b"ACK":
                return ack
            else:
                raise Exception("ACK inválido recibido")
        except socket.timeout:
            raise Exception("Timeout esperando ACK")
        except Exception as e:
            raise Exception(f"Error recibiendo ACK: {e}")

    def send_message(self, message: str):
        # este se usa desde user_info.client
        encrypted_message = caesar_encrypt(message, SHIFT)
        self.client_socket.send(encrypted_message.encode())
        data = self.client_socket.recv(self.buffer_size).decode()
        decrypted_data = caesar_decrypt(data, SHIFT)
        if decrypted_data == "ACK":
            logger.info("Mensaje enviado correctamente.")
        return decrypted_data
    
    def send_fragment(self, file_data):
        # este se usa desde user_info.client_files
        # logger.debug("Enviando fragmento de archivo... %s", file_data)
        self.client_socket.sendall(file_data)

    def close(self):
        self.client_socket.close()

class FileSenderWorker(QThread):
    progress = pyqtSignal(int, str)  # Señal para actualizar el progreso
    progress_label = pyqtSignal(str, str)  # Señal para actualizar el label de la barra de progreso
    finished = pyqtSignal()     # Señal para indicar que el envío terminó
    error = pyqtSignal(str)     # Señal para manejar errores

    def __init__(self, file_path, recipient_nickname, sender_nickname, client_socket, client_socket_files):
        super().__init__()
        self.file_path = file_path
        self.sender_nickname = sender_nickname
        self.recipient_nickname = recipient_nickname # Persona a la que le estamos mandado el archivo
        self.client_socket = client_socket
        self.client_socket_files = client_socket_files

    def send_with_retry(self, fragment, max_retries=3, timeout=2):
        retries = 0
        while retries < max_retries:
            self.client_socket_files.send_fragment(fragment)  # Envía el fragmento
            
            try: # Esperar ACK del receptor
                ack = self.client_socket_files.client_socket.recv(1024)  # Recibe el ACK
                ack_decrypted = caesar_decrypt(ack.decode('utf-8'), SHIFT)  # Descifra el ACK
                if ack_decrypted == "ACK":
                    return True  # ACK recibido, fragmento enviado correctamente
            except Exception as e:
                logger.error("Error recibiendo ACK: %s", e)
                logger.warning(f"No se recibió ACK. Reintentando... ({retries + 1}/{max_retries})")
            
            retries += 1
            time.sleep(2)  # Esperar antes de reintentar
        
        logger.error(f"No se pudo enviar el fragmento después de {max_retries} intentos.")
        return False  # No se pudo enviar el fragmento después de los reintentos

    def run(self): # este se llama cuando se hace start()
        """Envía el archivo en segundo plano."""
        try:
            # Obtener metadatos del archivo
            file_name = os.path.basename(self.file_path)
            file_size = os.path.getsize(self.file_path)

            # Enviar metadatos del archivo
            self.client_socket.send_message(f"FILE:{file_name}:{file_size}")

            # Enviar marcador de inicio
            info_marker = f"INICIO_DEL_ARCHIVO:{file_name}:{file_size}:{self.sender_nickname}".encode('utf-8')
            if not self.send_with_retry(info_marker):
                raise Exception("No se pudo enviar el marcador de inicio del archivo.")

            self.progress_label.emit(f"Enviando {file_name}...", self.recipient_nickname)

            # Enviar el archivo en fragmentos
            with open(self.file_path, 'rb') as file:
                sent_size = 0
                while True:
                    chunk = file.read(1024)
                    if not chunk:
                        break
                    if not self.send_with_retry(chunk):
                        raise Exception(f"No se pudo enviar un fragmento del archivo {file_name}.")
                    sent_size += len(chunk)
                    progress = int((sent_size / file_size) * 100)
                    # desde aqui se llama a la señal de progreso: def update_progress en ChatroomWindows
                    self.progress.emit(progress, self.recipient_nickname)  # Emitir progreso

            # Enviar marcador de fin
            if not self.send_with_retry(b":FIN_DEL_ARCHIVO:"):
                raise Exception("No se pudo enviar el marcador de fin del archivo.")

            self.progress_label.emit(f"Enviado! {file_name}", self.recipient_nickname)
            self.finished.emit()  # Emitir señal de finalización

        except Exception as e:
            self.error.emit(str(e))  # Emitir error

class ProfilePictureSenderWorker():#QThread):
    #finished = pyqtSignal()     # Señal para indicar que el envío terminó
    #error = pyqtSignal(str)     # Señal para manejar errores

    def __init__(self, file_path, sender_nickname):
        super().__init__()
        self.file_path = file_path
        self.sender_nickname = sender_nickname

    def send_with_retry(self, client_socket_file, fragment, max_retries=3, timeout=2):
        retries = 0
        while retries < max_retries:
            client_socket_file.send_fragment(fragment)  # Envía el fragmento
            
            try: # Esperar ACK del receptor
                ack = client_socket_file.client_socket.recv(1024)  # Recibe el ACK
                ack_decrypted = caesar_decrypt(ack.decode('utf-8'), SHIFT)  # Descifra el ACK
                if ack_decrypted == "ACK":
                    return True  # ACK recibido, fragmento enviado correctamente
            except Exception as e:
                logger.error("Error recibiendo ACK: %s", e)
                logger.warning(f"No se recibió ACK. Reintentando... ({retries + 1}/{max_retries})")
            
            retries += 1
            time.sleep(2)  # Esperar antes de reintentar
        
        logger.error(f"No se pudo enviar el fragmento después de {max_retries} intentos.")
        return False  # No se pudo enviar el fragmento después de los reintentos

    def run(self): # este se llama cuando se hace start()
        """Envía el archivo en segundo plano."""
        # Obtener metadatos del archivo
        file_name = os.path.basename(self.file_path)
        file_size = os.path.getsize(self.file_path)

        for recipient_nickname, user_info in USER_INFO_BY_NICKNAME.items(): # enviar mi foto a todo el mundo
            client_socket_file = user_info.client_files
            # Enviar marcador de inicio
            info_marker = f"INICIO_DEL_PROFILE_PICTURE:{file_name}:{file_size}:{self.sender_nickname}".encode('utf-8')
            logger.debug("Enviando picture a %s, el path es %s, el info marker es %s", recipient_nickname, self.file_path, info_marker)
            if not self.send_with_retry(client_socket_file, info_marker):
                raise Exception("No se pudo enviar el marcador de inicio del profile picture.")

            # Enviar el archivo en fragmentos
            with open(self.file_path, 'rb') as file:
                sent_size = 0
                while True:
                    chunk = file.read(1024)
                    if not chunk:
                        break
                    if not self.send_with_retry(client_socket_file, chunk):
                        raise Exception(f"No se pudo enviar un fragmento del archivo {file_name}.")
                    sent_size += len(chunk)
            # Enviar marcador de fin
            if not self.send_with_retry(client_socket_file, b":FIN_DEL_PROFILE_PICTURE:"):
                raise Exception("No se pudo enviar el marcador de fin del archivo.")

            #self.finished.emit()  # Emitir señal de finalización

class ProgressBarWithLabel(QWidget):
    def __init__(self, label_text, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)

        # Crear el QLabel
        self.label = QLabel(label_text)
        self.layout.addWidget(self.label)

        # Crear el QProgressBar
        self.progress_bar = QProgressBar()
        self.layout.addWidget(self.progress_bar)

    def setValue(self, value):
        self.progress_bar.setValue(value)
    
    def setLabelText(self, text):
        self.label.setText(text)

    def getLabelTex(self):
        return self.label.text()

class ProfilePictureWidget(QWidget):
    # Señal personalizada que notifica cuando la foto se actualiza
    photo_updated = pyqtSignal(bytes, str)

    def __init__(self):
        super().__init__()
        self.photo_bytes = None
        self.picture_path = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Label para mostrar la foto de perfil
        self.profile_pic = QLabel(self)
        self.profile_pic.setFixedSize(100, 100)
        self.profile_pic.setAlignment(Qt.AlignCenter)
        self.profile_pic.setStyleSheet("border: 1px solid gray; border-radius: 50px;")

        # Botón para subir la foto
        btn_upload = QPushButton("Subir/Editar foto de perfil", self)
        btn_upload.clicked.connect(self.upload_picture)

        layout.addWidget(self.profile_pic)
        layout.addWidget(btn_upload)

        self.setLayout(layout)

    def upload_picture(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Seleccionar imagen", "", "Imágenes (*.png *.jpg *.jpeg *.bmp)")
        if file_name:
            self.picture_path = file_name
            # Abrir y convertir la imagen a PNG para estandarizar
            with Image.open(file_name) as img:
                img = img.convert("RGB")
                buffer = io.BytesIO()
                #img.save(buffer, format="PNG")
                img.save(buffer, format="JPEG")
                self.photo_bytes = buffer.getvalue()

            # Mostrar la imagen en el QLabel
            pixmap = QPixmap()
            pixmap.loadFromData(self.photo_bytes)
            self.profile_pic.setPixmap(pixmap.scaled(100, 100, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation))

            # Emitir la señal para notificar la actualización
            self.photo_updated.emit(self.photo_bytes, self.picture_path)

    def get_image_as_bytes(self):
        return self.photo_bytes
    
    def get_picture_path(self):
        return self.picture_path

class ImageViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.picture_path = None

    def save_picture_path(self, picture_path):
        self.picture_path = picture_path

    def init_ui(self):
        # Layout principal
        layout = QVBoxLayout()

        # QLabel para mostrar la imagen
        self.image_label = QLabel(self)
        self.image_label.setFixedSize(100, 100)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("border: 1px solid gray; border-radius: 50px;")

        layout.addWidget(self.image_label)
        self.setLayout(layout)

    def set_image_from_path(self, picture_path):
        """
        Método para cargar una imagen desde un archivo y mostrarla en el QLabel.
        :param image_path: Ruta de la imagen.
        """
        # Abrir y convertir la imagen a PNG para estandarizar
        logger.debug("Cargando imagen desde %s", picture_path)
        with Image.open(picture_path) as img:
            img = img.convert("RGB")
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG")
            photo_bytes = buffer.getvalue()
            self.set_image_from_bytes(photo_bytes)

    def set_image_from_bytes(self, image_bytes):
        """
        Método para cargar una imagen desde bytes y mostrarla en el QLabel.
        :param image_bytes: Bytes de la imagen.
        """

        # Convertir los bytes a una imagen usando Pillow
        image = Image.open(io.BytesIO(image_bytes))

        # Convertir la imagen a un formato compatible con QPixmap
        image = image.convert("RGB")
        
        # Guardar la imagen en un buffer en formato JPEG
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG")
        jpeg_data = buffer.getvalue()

        # Crear un QPixmap desde los datos de la imagen
        pixmap = QPixmap()
        pixmap.loadFromData(jpeg_data, "JPEG")

        # Escalar el QPixmap al tamaño del QLabel
        
        self.image_label.setPixmap(
            pixmap.scaled(100, 100, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
        )


class ChatroomWindows(QWidget):
    def __init__(self, nickname: str):
        super().__init__()
        self.sender_nickname = nickname
        self.my_photo_widget = None

        self.chat_windows = {} # Diccionario para almacenar las ventanas de cada chat privado
        self.text_box = {} # Diccionario para almacenar los QTextEdit de cada chat privado
        self.entry_message = {} # Diccionario para almacenar los QLineEdit de cada chat privado
        self.file_button = {} # Diccionario para almacenar los QPushButton de cada chat privado
        self.progress_bar = {} # Diccionario para almacenar los QProgressBar de cada chat privado
        self.progress_bar_received = {} # Diccionario para almacenar los QProgressBar de recepcion de archivos por cada chat privado
        self.check_workers = {} # Diccionario para almacenar los workers de cada chat privado
        self.check_threads = {} # Diccionario para almacenar los threads de cada chat privado

        self.layout = {} # Diccionario para almacenar los layout de cada chat privado
        self.received_files = {} # Diccionario para almacenar los archivos recibidos, key: sender, value: dict of files
        self.profile_pictures = {} # Diccionario para almacenar las fotos de perfil de los usuarios
        
        # buttons to play and save files
        self.save_button = {} # Diccionario para almacenar los botones de guardar archivo
        self.play_button = {} # Diccionario para almacenar los botones de reproducir archivo
        self.player_widget = {} # Diccionario para almacenar los reproductores de video
        
        # workers
        self.play_file_worker = {} # Diccionario para almacenar los workers de reproducción de archivos, key: nombre del archivo, value: worker
        self.file_sender_worker = {} # Diccionario para almacenar los workers de envio de archivos, key: nombre del archivo mas el nickname del destinatario, value: worker

        self.group_chat = None # Ventana de chat grupal

        self.setWindowTitle(f"Chatroom de {self.sender_nickname}")
        self.setGeometry(100, 100, 300, 300)
        self.main_layout = QVBoxLayout()

        self.list_users = QListWidget()
        self.list_users.setLayout(QVBoxLayout())

        # Mi foto de perfil
        self.my_photo_widget = ProfilePictureWidget()
        self.my_photo_widget.photo_updated.connect(self.send_my_photo_profile_to_users)
        self.main_layout.addWidget(self.my_photo_widget)

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

        self.btn_cerrar = QPushButton("Cerrar sesión", self)
        self.btn_cerrar.clicked.connect(terminate_application)

        # Add widgets to the layout
        self.main_layout.addWidget(text_title)
        self.main_layout.addWidget(self.btn_create_group)
        self.main_layout.addWidget(self.list_users)
        self.main_layout.addWidget(self.btn_cerrar)

        # Establecer el layout principal en la ventana
        self.setLayout(self.main_layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_user_list)
        self.timer.start(1000)

        self.timer_to_join = QTimer.singleShot(2000, self.send_request_to_join_chatroom)

    def update_group_chat(self, sender_nickname, mensaje):
        # Aquí actualizamos la interfaz de forma segura en el hilo principal
        # Asegúrate de usar la clave correcta, por ejemplo, el nickname del destinatario
        logger.debug("Mensaje grupal recibido de %s: %s", sender_nickname, mensaje)
        self.chat_display.append(f"{sender_nickname}: {mensaje}")

    def update_photo_of_user(self, sender_nickname: str, photo_bytes: bytes):
        """Actualiza la foto de perfil de un usuario."""
        if sender_nickname in self.profile_pictures: # si tenemos un chat abierto con esa persona
            user_info = USER_INFO_BY_NICKNAME[sender_nickname]
            user_info.profile_picture = photo_bytes
            self.profile_pictures[sender_nickname].set_image_from_bytes(photo_bytes)

    def update_private_chat(self, mensaje):
        """ Este se llama desde self.messageReceived.emit(mensaje) en CheckPrivateIncomingMessagesWorker """
        # Aquí actualizamos la interfaz de forma segura en el hilo principal
        # Asegúrate de usar la clave correcta, por ejemplo, el nickname del destinatario
        logger.debug("Mensaje privado recibido en update_private_chat: %s", mensaje)
        
        sender_nickname = mensaje.split(":")[0]
        check_action = mensaje.split(":")[1]
        if check_action == "FILE": # Actualizar la interfaz para decir que se está recibiendo un archivo
            sender_nickname, _, file_name, file_size = mensaje.split(":")
            file_size = int(file_size)
            if sender_nickname in self.text_box:
                self.text_box[sender_nickname].append(f"{sender_nickname}: Recibiendo archivo: {file_name}...")
            else:
                logger.error("No se encontró la clave en text_box")
            # TODO: Hacer algo en la interfaz para mostrar que se está recibiendo un archivo
        else:
            mensaje = check_action
            logger.debug("Mensaje recibido de %s: %s", sender_nickname, mensaje)
            if sender_nickname in self.text_box:
                self.text_box[sender_nickname].append(f"{sender_nickname}: {mensaje}")
            else:
                logger.error("No se encontró la clave en text_box")

    def delete_player_widget(self, sender_nickname, file_name):
        if sender_nickname in self.player_widget:
            if file_name in self.player_widget[sender_nickname]:
                #self.player_widget[sender_nickname][file_name].close()
                del self.player_widget[sender_nickname][file_name]
                logger.debug("Player widget eliminado de la lista")

        if sender_nickname in self.play_button:
            if file_name in self.play_button[sender_nickname]:
                self.play_button[sender_nickname][file_name].setEnabled(True)

    def play_file(self, sender_nickame, file_name):
        """Abre la ventana de reproducción de video."""
        # Mostrar la ventana del reproductor
        if sender_nickame not in self.player_widget:
            self.player_widget[sender_nickame] = {}

        file_path = self.received_files[sender_nickame][file_name]

        if file_name not in self.player_widget[sender_nickame]:
            self.player_widget[sender_nickame][file_name] = Player(file_path)
            # borrar la instancia cuando se cierre la ventana
            self.player_widget[sender_nickame][file_name].window_closed.connect(lambda: self.delete_player_widget(sender_nickame, file_name))
            self.play_button[sender_nickame][file_name].setText(f"Reproduciendo: {file_name}")
            self.play_button[sender_nickame][file_name].setEnabled(False)

        self.player_widget[sender_nickame][file_name].show()

        # Cambiar el tamaño de la ventana
        self.player_widget[sender_nickame][file_name].resize(640, 480)

        # Abrir un archivo de video (opcional)
        self.player_widget[sender_nickame][file_name].OpenFile()

    def save_file(self, sender_nickname, temp_file_path, file_name):
        """ Guarda el archivo en la ubicación seleccionada por el usuario """
        if file_name not in self.received_files[sender_nickname]: # Si el archivo ya fue guardado, no hacer nada
            return
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar archivo", file_name, "Todos los archivos (*)", options=options
        )
        if file_path:
            # Mover el archivo temporal a la ubicación seleccionada
            shutil.move(temp_file_path, file_path)
            logger.debug("Archivo guardado en: %s", file_path)
            self.text_box[sender_nickname].append(f"Archivo {file_name} guardado en {file_path}.")

            # Deshabilitar el botón de guardar
            self.save_button[sender_nickname][file_name].setEnabled(False)
            self.save_button[sender_nickname][file_name].setText(f"Archivo ya fue guardado: {file_name}.")
            
            temp_file_path = self.received_files[sender_nickname][file_name]
            logger.debug("Play button cambia de temp path: %s, al nuevo path %s", temp_file_path, file_path)
            self.received_files[sender_nickname][file_name] = file_path

    def create_temporary_file(self, sender_nickname, file_name, temp_file_path):
        """Crea un archivo temporal y lo prepara para recibir fragmentos."""
        try:
            # Guardar la ruta del archivo temporal en el diccionario
            if sender_nickname not in self.received_files:
                self.received_files[sender_nickname] = {}
            self.received_files[sender_nickname][file_name] = temp_file_path
            logger.debug("Preparado para recibir el archivo %s en un archivo temporal %s", file_name, temp_file_path)
            return temp_file_path

        except Exception as e:
            logger.error(f"Error al crear archivo temporal: {e}")
            raise

    def update_private_chat_files(self, sender_nickname, file_name, temp_file_path, is_profile_picture, percentage=0):
        """ Este se llama desde self.fragmentReceived.emit en CheckPrivateIncomingFilesWorker """

        if is_profile_picture:
            if sender_nickname in self.profile_pictures:
                self.profile_pictures[sender_nickname] = ImageViewerWidget()


        if sender_nickname not in self.save_button:
            self.save_button[sender_nickname] = {}

        if file_name not in self.save_button[sender_nickname]:
            self.save_button[sender_nickname][file_name] = QPushButton(f"[Progress] {file_name}: 1%")
            self.save_button[sender_nickname][file_name].setEnabled(False)
            self.layout[sender_nickname].layout().addWidget(self.save_button[sender_nickname][file_name])

        if sender_nickname not in self.play_button:
            self.play_button[sender_nickname] = {}

        if file_name not in self.play_button[sender_nickname]:
            self.play_button[sender_nickname][file_name] = QPushButton(f"[Play] {file_name}")
            self.play_button[sender_nickname][file_name].setEnabled(True)
            self.layout[sender_nickname].layout().addWidget(self.play_button[sender_nickname][file_name])
            # TODO luego este debe ser el path donde lo guardo el usuario
            self.play_button[sender_nickname][file_name].clicked.connect(lambda: self.play_file(sender_nickname, file_name))

        if file_name not in self.progress_bar_received[sender_nickname].getLabelTex():
            self.progress_bar_received[sender_nickname].setLabelText(f"Recibiendo {file_name}...")

        if percentage == 100: # para evitar que se ejecute mas de una vez
            temp_file_path = self.received_files[sender_nickname][file_name]
            self.save_button[sender_nickname][file_name].setText(f"[Save File] {file_name}")
            self.save_button[sender_nickname][file_name].setEnabled(True)
            self.save_button[sender_nickname][file_name].clicked.connect(lambda: self.save_file(sender_nickname, temp_file_path, file_name))
            self.progress_bar_received[sender_nickname].setLabelText(f"Recibido! {file_name}")
            self.progress_bar_received[sender_nickname].setValue(percentage)
            self.let_know_sender_i_received_file(sender_nickname, file_name)
            self.text_box[sender_nickname].append(f"Archivo recibido correctamente: {file_name}.")
        else:
            self.save_button[sender_nickname][file_name].setText(f"[Progress] {file_name}: {percentage}%")
            self.progress_bar_received[sender_nickname].setValue(percentage)

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
            port = get_free_port()
            logger.debug("Creando server para recibir mensajes escritos de %s en el puerto %s", recipient_nickname, port)
            server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_messages_from_{recipient_nickname}", get_ip_local(), port)
            server.start()
            # esperar para que el servidor se inicie
            logger.debug("Esperando 2 SEGUNDOS a que el servidor de mensajes se inicie antes de crear el worker...")
            time.sleep(2)
            user_info.server_listening = server

            # crear worker para procesar mensajes entrantes y actualizar la GUI
            # esto se hizo porque con hilos normales la interfaz se congelaba
            self.check_workers[recipient_nickname] = CheckPrivateIncomingMessagesWorker(server, recipient_nickname)
            self.check_threads[recipient_nickname] = QThread()
            self.check_workers[recipient_nickname].moveToThread(self.check_threads[recipient_nickname])
            self.check_workers[recipient_nickname].messageReceived.connect(self.update_private_chat)
            self.check_threads[recipient_nickname].started.connect(self.check_workers[recipient_nickname].process_messages)
            self.check_threads[recipient_nickname].start()

            # esperar un segundo para que el server se inicie
            logger.debug("Esperando 2 SEGUNDOS a que el Worker de mensajes se inicie antes de solicitar el cliente...")
            time.sleep(2)

            # si el recipient no tiene un cliente para escribirnos hay
            # que enviarle una solicitud al recipient para que cree uno
            self.send_request_to_create_tcp_client(recipient_nickname, port)
               
            # si el recipient no tiene un servidor tcp para recibir mensajes
            # de este sender, hay que enviarle una solicitud al recipient
            # para que cree uno
            time.sleep(2)
            if user_info.client is None:
                self.send_request_to_create_tcp_server(recipient_nickname)

        # crear servidor para recibir archivos de la persona con la que quiero chatear
        if user_info.server_listening_files is None:
            # si el sender no tiene un servidor tcp para recibir archivos del recipient, hay que crearlo
            port = get_free_port()
            logger.debug("Creando server para recibir ARCHIVOS de %s en el puerto %s", recipient_nickname, port)
            server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_files_from_{recipient_nickname}", get_ip_local(), port, "FILES")
            server.start()
            # esperar para que el servidor se inicie
            logger.debug("Esperando 2 SEGUNDOS a que el servidor de archivos se inicie antes de crear el worker...")
            time.sleep(2)
            user_info.server_listening_files = server

            # crear worker para procesar archivos entrantes y actualizar la GUI
            # esto se hizo porque con hilos normales la interfaz se congelaba
            self.check_workers[recipient_nickname + "files"] = CheckPrivateIncomingFilesWorker(server, recipient_nickname)
            self.check_threads[recipient_nickname + "files"] = QThread()
            self.check_workers[recipient_nickname + "files"].moveToThread(self.check_threads[recipient_nickname + "files"])
            self.check_workers[recipient_nickname + "files"].fragmentReceived.connect(self.update_private_chat_files)
            self.check_workers[recipient_nickname + "files"].createTemporaryFile.connect(self.create_temporary_file)
            self.check_workers[recipient_nickname + "files"].createProfilePicture.connect(self.create_profile_picture)
            self.check_workers[recipient_nickname + "files"].updateProfilePicture.connect(self.update_profile_picture)
            self.check_threads[recipient_nickname + "files"].started.connect(self.check_workers[recipient_nickname + "files"].process_files)
            self.check_threads[recipient_nickname + "files"].start()

            # esperar un segundo para que el server se inicie
            logger.debug("Esperando 2 SEGUNDOS a que el Worker de archivos se inicie antes de solicitar el cliente...")
            time.sleep(2)

            # si el otro nodo no tiene un cliente para escribirnos hay
            # que enviarle una solicitud para que cree uno
            logger.debug("Oye %s crea un cliente para que me mandes ACKs de mis archivos", recipient_nickname)
            self.send_request_to_create_tcp_client_files(recipient_nickname, port)
            
            # si el otro nodo no tiene un servidor tcp para recibir archivos
            # de este sender, hay que enviarle una solicitud al recipient
            # para que cree uno
            time.sleep(2)
            if user_info.client_files is None:
                self.send_request_to_create_tcp_server_files(recipient_nickname)

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
            port = get_free_port()
            logger.debug("Creando server para recibir mensajes escritos de %s en el puerto %s", recipient_nickname, port)
            server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_messages_from_{recipient_nickname}", get_ip_local(), port)
            server.start()
            logger.debug("Esperando 2 SEGUNDOS a que el servidor de mensajes se inicie antes de crear el worker...")
            time.sleep(2)
            user_info.server_listening = server

            # crear worker para procesar mensajes entrantes y actualizar la GUI
            self.check_workers[recipient_nickname] = CheckPrivateIncomingMessagesWorker(server, recipient_nickname)
            self.check_threads[recipient_nickname] = QThread()
            self.check_workers[recipient_nickname].moveToThread(self.check_threads[recipient_nickname])
            self.check_workers[recipient_nickname].messageReceived.connect(self.update_private_chat)
            self.check_threads[recipient_nickname].started.connect(self.check_workers[recipient_nickname].process_messages)
            self.check_threads[recipient_nickname].start()

            logger.debug("Esperando 2 SEGUNDOS a que el Worker de mensajes se inicie antes de solicitar el cliente...")
            time.sleep(2)
            user_info.server_listening = server

            # si el recipient no tiene un cliente para escribirnos hay
            # que enviarle una solicitud al recipient para que cree uno
            self.send_request_to_create_tcp_client(recipient_nickname, port)

        # crear servidor para recibir archivos de la persona con la que quiero chatear
        if user_info.server_listening_files is None:
            # si el sender no tiene un servidor tcp para recibir archivos del recipient, hay que crearlo
            port = get_free_port()
            logger.debug("Creando server para recibir ARCHIVOS de %s en el puerto %s", recipient_nickname, port)
            server = ServerTCP(f"server_of_{self.sender_nickname}_to_receive_files_from_{recipient_nickname}", get_ip_local(), port, "FILES")
            server.start()
            user_info.server_listening = server

            # crear worker para procesar archivos entrantes y actualizar la GUI
            self.check_workers[recipient_nickname + "files"] = CheckPrivateIncomingFilesWorker(server, recipient_nickname)
            self.check_threads[recipient_nickname + "files"] = QThread()
            self.check_workers[recipient_nickname + "files"].moveToThread(self.check_threads[recipient_nickname + "files"])
            self.check_workers[recipient_nickname + "files"].fragmentReceived.connect(self.update_private_chat_files)
            self.check_workers[recipient_nickname + "files"].createTemporaryFile.connect(self.create_temporary_file)
            self.check_workers[recipient_nickname + "files"].createProfilePicture.connect(self.create_profile_picture)
            self.check_workers[recipient_nickname + "files"].updateProfilePicture.connect(self.update_profile_picture)
            self.check_threads[recipient_nickname + "files"].started.connect(self.check_workers[recipient_nickname + "files"].process_files)
            self.check_threads[recipient_nickname + "files"].start()

            # esperar un segundo para que el server se inicie
            logger.debug("Esperando 2 SEGUNDOS a que el Worker de archivos se inicie antes de solicitar el cliente...")
            time.sleep(2)

            # si el recipient no tiene un cliente para escribirnos hay
            # que enviarle una solicitud al recipient para que cree uno
            self.send_request_to_create_tcp_client_files(recipient_nickname, port)

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
        self.chat_input.textChanged.connect(lambda: self.replace_emoticons(self.chat_input))
        self.chat_input.returnPressed.connect(self.send_message_to_group)
        self.chat_input.setPlaceholderText("Escribe tu mensaje aquí...")
        self.group_layout.addWidget(self.chat_input)

        # Botón para enviar mensajes
        send_button = QPushButton('Enviar')
        send_button.clicked.connect(self.send_message_to_group)
        self.group_layout.addWidget(send_button)
        self.group_chat.show()

    def let_know_sender_i_received_file(self, sender_nickname, file_name):
        sender_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
        if sender_info:
            client_socket = sender_info.client
            client_socket.send_message(f"Archivo {file_name} enviado satisfactoriamente.")

    def send_with_retry(self, client_socket: ClientTCP, fragment, max_retries=3, timeout=2):
        retries = 0
        while retries < max_retries:
            client_socket.send_fragment(fragment) # sendall
            
            try: # Esperar ACK del receptor
                ack = client_socket.client_socket.recv(1024)  # Recibe el ACK
                ack_decrypted = caesar_decrypt(ack.decode('utf-8'), SHIFT)  # Descifra el ACK
                if ack_decrypted == "ACK":
                    return True  # ACK recibido, fragmento enviado correctamente
            except Exception as e:
                logger.error("Error recibiendo ACK: %s", e)
                logger.warning(f"No se recibió ACK. Reintentando... ({retries + 1}/{max_retries})")
            
            retries += 1
            time.sleep(2)  # Esperar antes de reintentar
        
        logger.error(f"No se pudo enviar el fragmento después de {max_retries} intentos.")
        return False  # No se pudo enviar el fragmento después de los reintentos

    def select_and_send_file(self, recipient_nickname):
        logger.debug("Seleccionar archivo para enviar a %s", recipient_nickname)
        file_path, _ = QFileDialog.getOpenFileName()
        if not file_path:
            return
        file_name = os.path.basename(file_path)

        client_socket = USER_INFO_BY_NICKNAME[recipient_nickname].client
        logger.debug("Obtener el client_files de %s", recipient_nickname)
        client_socket_files = USER_INFO_BY_NICKNAME[recipient_nickname].client_files
        self.text_box[recipient_nickname].append(f"Enviando archivo... {file_path}")

        # Crear y configurar el worker
        self.file_sender_worker[f"{recipient_nickname}:{file_name}"] = FileSenderWorker(
            file_path=file_path,
            recipient_nickname=recipient_nickname, # el recipient es el que recibirá el archivo
            sender_nickname=self.sender_nickname, # el sender soy yo
            client_socket=client_socket,
            client_socket_files=client_socket_files,
        )

        # Conectar señales
        self.file_sender_worker[f"{recipient_nickname}:{file_name}"].progress.connect(self.update_progress)
        self.file_sender_worker[f"{recipient_nickname}:{file_name}"].progress_label.connect(self.update_progress_label)
        self.file_sender_worker[f"{recipient_nickname}:{file_name}"].finished.connect(self.on_file_sent)
        self.file_sender_worker[f"{recipient_nickname}:{file_name}"].error.connect(self.show_error)

        # Iniciar el hilo, esto llama a FileSenderWorker.run()
        self.file_sender_worker[f"{recipient_nickname}:{file_name}"].start()

    def update_progress_label(self, label_text, recipient_nickname):
        """Actualiza el texto de la barra de progreso."""
        self.progress_bar[recipient_nickname].setLabelText(label_text)

    def update_progress(self, progress, recipient_nickname):
        """Actualiza la barra de progreso o muestra el progreso."""
        self.progress_bar[recipient_nickname].setValue(progress)
        # Aquí puedes actualizar la interfaz de usuario con el progreso

    def on_file_sent(self):
        """Maneja la finalización del envío."""
        #if self.worker_thread:
        #    self.worker_thread.quit()  # Solicitar la finalización del hilo
        #    self.worker_thread.wait()  # Esperar a que el hilo termine
        #    self.worker_thread = None  # Liberar la referencia
        logger.info("Archivo enviado correctamente. Hilo terminado y limpiado.")
        # Aquí puedes mostrar un mensaje en la interfaz de usuario

    def show_error(self, error_message):
        """Maneja errores."""
        logger.error(f"Error: {error_message}")
        # Aquí puedes mostrar un mensaje de error en la interfaz de usuario

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
            self.layout[recipient_nickname] = QVBoxLayout(central_widget)

            # Frame para la barra de progreso al recibir un archivo
            frame_archivo_recibido = QWidget()
            frame_archivo_recibido.setLayout(QHBoxLayout())

            # Foto de perfil del otro usuario
            self.profile_pictures[recipient_nickname] = ImageViewerWidget()
            #image_profile_widget.set_image_from_bytes(user_info.profile_pic) # mandar los bytes de la fotos del otro usuario
            self.layout[recipient_nickname].addWidget(self.profile_pictures[recipient_nickname])

            # Barra de progreso de recibido
            self.progress_bar_received[recipient_nickname] = ProgressBarWithLabel("Ningun archivo recibido por ahora")
            self.progress_bar_received[recipient_nickname].setValue(0)
            frame_archivo_recibido.layout().addWidget(self.progress_bar_received[recipient_nickname])

            self.layout[recipient_nickname].addWidget(frame_archivo_recibido)

            # Frame para el botón de archivos y la barra de progreso
            frame_archivo = QWidget()
            frame_archivo.setLayout(QHBoxLayout())

            # Boton para mandar archivos
            self.file_button[recipient_nickname] = QPushButton("Send File")
            self.file_button[recipient_nickname].clicked.connect(lambda: self.select_and_send_file(recipient_nickname))
            frame_archivo.layout().addWidget(self.file_button[recipient_nickname])

            # Barra de progreso
            self.progress_bar[recipient_nickname] = ProgressBarWithLabel("Ningun archivo enviado por ahora")
            self.progress_bar[recipient_nickname].setValue(0)
            frame_archivo.layout().addWidget(self.progress_bar[recipient_nickname])

            self.layout[recipient_nickname].addWidget(frame_archivo)

            # Área de visualización de mensajes
            self.text_box[recipient_nickname] = QTextEdit(self.chat_windows[recipient_nickname])
            self.text_box[recipient_nickname].setReadOnly(True)
            self.text_box[recipient_nickname].setFont(self.get_font(12))
            self.layout[recipient_nickname].addWidget(self.text_box[recipient_nickname])

            # Cuadro de texto para escribir mensajes
            frame_entrada = QWidget()
            frame_entrada.setLayout(QHBoxLayout())

            self.entry_message[recipient_nickname] = QLineEdit(frame_entrada)
            self.entry_message[recipient_nickname].textChanged.connect(lambda: self.replace_emoticons(self.entry_message[recipient_nickname]))
            self.entry_message[recipient_nickname].returnPressed.connect(lambda: self.send_private_message(recipient_nickname))
            self.entry_message[recipient_nickname].setFont(self.get_font(12))
            frame_entrada.layout().addWidget(self.entry_message[recipient_nickname])

            # Botón para enviar mensajes
            btn_enviar = QPushButton("Enviar", frame_entrada)
            btn_enviar.setFont(self.get_font(12))
            btn_enviar.clicked.connect(lambda: self.send_private_message(recipient_nickname))
            frame_entrada.layout().addWidget(btn_enviar)

            self.layout[recipient_nickname].addWidget(frame_entrada)

            user_info.private_chat = self.chat_windows[recipient_nickname]
            user_info.visual_chat = self.text_box[recipient_nickname]
            user_info.entry_message = self.entry_message[recipient_nickname]

            self.chat_windows[recipient_nickname].show()
            logger.debug("Chat con %s creado.", recipient_nickname)

    def replace_emoticons(self, entry: QLineEdit):
        emoticon_map = {
            ':)': '😊',
            ':D': '😄',
            ';)': '😉'
        }

        text = entry.text()
        for emoticon, emoji in emoticon_map.items():
            if emoticon in text:
                text = text.replace(emoticon, emoji)

        # Desconectar y reconectar para evitar recursión infinita
        entry.blockSignals(True)
        entry.setText(text)
        entry.blockSignals(False)

    def send_private_message(self, recipient_nickname: str):
        """ Envía un mensaje y lo muestra en el área de mensajes. """
        message = self.entry_message[recipient_nickname].text()
        if message.strip():  # Verificar que el mensaje no esté vacío

            # Mostrar el mensaje en el área de mensajes
            self.text_box[recipient_nickname].append(f"Tú: {message}")
            self.entry_message[recipient_nickname].clear()

            for nickname, user_info in USER_INFO_BY_NICKNAME.items():
                logger.debug("nickname %s", nickname)
                logger.debug("recipient_nickname %s", recipient_nickname)
                logger.debug("user_info.client %s", user_info.client)
                logger.debug("user_info.server_listening %s", user_info.server_listening)
                logger.debug("user_info.private_chat %s", user_info.private_chat)
                logger.debug("user_info.visual_chat %s", user_info.visual_chat)
                logger.debug("user_info.entry_message %s", user_info.entry_message)

            logger.debug("Enviando mensaje a %s: %s", recipient_nickname, message)
            try:
                recipient_user_info = USER_INFO_BY_NICKNAME[recipient_nickname]
                client_socket = recipient_user_info.client
                data = client_socket.send_message(message)
                logger.debug("Servidor: %s", data)
            except Exception as e:
                logger.error("Error al enviar mensaje en send_private_message: %s", e)

    def send_request_to_create_tcp_server(self, recipient_nickname):
        """ This method send a request to create a tcp server in the recipient side
        """
        action = "CREATE_TCP_SERVER"
        sender = self.sender_nickname
        recipient = recipient_nickname
        message = f"{action}:{sender}:{recipient}"
        self.send_message_orchestrator(message)

    def send_request_to_create_tcp_server_files(self, recipient_nickname):
        """ This method send a request to create a tcp server in the recipient side
        """
        action = "CREATE_TCP_SERVER_FILES"
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

    def send_request_to_create_tcp_client_files(self, recipient_nickname, port):
        """ This method send a request to create a tcp client in the recipient side
        """
        action = "CREATE_TCP_CLIENT_FILES"
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

    def create_profile_picture(self, sender_nickname, file_name, temp_file_path):
        self.profile_pictures[sender_nickname].save_picture_path(temp_file_path)

    def update_profile_picture(self, sender_nickname, picture_path):
        self.profile_pictures[sender_nickname].set_image_from_path(picture_path)

    def send_my_photo_profile_to_users(self):
        profile_picture_worker = ProfilePictureSenderWorker(
            file_path=self.my_photo_widget.get_picture_path(),
            sender_nickname=self.sender_nickname, # el sender soy yo
        )
        profile_picture_worker.run()
        #profile_picture_worker.finished.connect(self.on_file_sent)
        #profile_picture_worker.error.connect(self.show_error)
        #logger.debug("Iniciar el hilo para mandar mi foto de perfil")
        #profile_picture_worker.start()





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
        logger.info("CheckPrivateIncomingMessagesWorker creado para %s", sender_nickname)

    def process_messages(self):
        while self.running:
            try:
                mensaje, address = self.server.incoming_queue.get(timeout=0.1) # TODO: guardar el address
                logger.debug("Mensaje recibido en CheckPrivateIncomingMessagesWorker process_messages: %s", mensaje)
                # esto llama a update_private_chat
                self.messageReceived.emit(f"{self.sender_nickname}:{mensaje}")
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error en CheckPrivateIncomingMessagesWorker: {e}")
                break

    def stop(self):
        self.running = False

class CheckPrivateIncomingFilesWorker(QObject):
    createTemporaryFile = pyqtSignal(str, str, str)
    createProfilePicture = pyqtSignal(str, str, str)
    updateProfilePicture = pyqtSignal(str, str)
    fragmentReceived = pyqtSignal(str, str, str, int)

    def __init__(self, server: ServerTCP, sender_nickname):
        super().__init__()
        self.server = server
        self.sender_nickname = sender_nickname # nickname del usuario que envía el archivo
        self.running = True
        self.client_files: ClientTCP = None # TODO: esto ya no es necesario, borrarlo luego
        logger.info("CheckPrivateIncomingFilesWorker creado para %s", sender_nickname)

    def process_files(self):
        file_size = 0
        received_size = 0
        sender_nickname = ""
        file_name = ""
        temp_file_path = ""
        is_profile_picture = False

        # TODO: esto ya no es necesario, borrarlo luego
        logger.debug("Intentando obtener el cliente de %s", self.sender_nickname)
        get_client = True
        while get_client:
            if self.client_files is None:
                self.client_files = USER_INFO_BY_NICKNAME[self.sender_nickname].client_files
                if self.client_files is not None:
                    logger.debug("CLIENTE DE ARCHIVOS DE %s OBTENIDO!!!", self.sender_nickname)
                    get_client = False

        # Variable para almacenar el tiempo de la última ejecución
        last_execution_time = time.time()
        while self.running:
            try:
                mensaje, address = self.server.incoming_queue.get(timeout=0.1)
                # Verificar si es el marcador de fin de archivo
                if b":FIN_DEL_ARCHIVO:" in mensaje:
                    logger.debug("Fin de envio del archivo %s... from: %s", file_name, self.sender_nickname)
                    self.fragmentReceived.emit(self.sender_nickname, file_name, temp_file_path, 100) # TODO esto hace que se mande dos veces el mismo mensaje
                    continue

                if b":FIN_DEL_PROFILE_PICTURE:" in mensaje:
                    logger.debug("Fin de envio de la foto de perfil de %s...", self.sender_nickname)
                    is_profile_picture = False
                    time.sleep(1)
                    self.updateProfilePicture.emit(self.sender_nickname, temp_file_path)
                    continue

                logger.debug("SI que llegó ALGO")
                try:
                    decoded_data = mensaje.decode('utf-8')
                    logger.debug("*** Datos recibidos en process_files: %s", decoded_data)

                    # Verificar si es el marcador de información del archivo
                    if decoded_data.startswith("INICIO_DEL_ARCHIVO:"):
                        parts = decoded_data.split(":")
                        if len(parts) >= 4:
                            received_size = 0
                            file_name = parts[1]  # Nombre del archivo
                            file_size = int(parts[2])  # Tamaño del archivo
                            sender_nickname = parts[3]  # Nickname del remitente

                            # Crear un archivo temporal
                            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb') # No se borrará el archivo al cerrarlo
                            temp_file_path = temp_file.name
                            temp_file.close()  # Cerrar el archivo para que pueda ser escrito más tarde

                            # Dar permisos de lectura y escritura y evitar
                            # el error en Windows:
                            # Permission denied: 'C:\\Users\\Ahome\\AppData\\Local\\Temp\\tmpa05loims
                            os.chmod(temp_file_path, stat.S_IREAD | stat.S_IWRITE)

                            self.createTemporaryFile.emit(self.sender_nickname, file_name, temp_file_path)  # Guardar path de archivo temporal

                            # El temp_file_path es la ruta del archivo temporal
                            logger.debug("Temporary file path: %s", temp_file_path)

                            # Abrir el archivo para escritura
                            logger.debug("Datos recibidos\nNombre: %s\nTamaño: %s\nRemitente: %s", file_name, file_size, self.sender_nickname)

                            last_execution_time = time.time()


                    # Verificar si es el marcador de información del archivo
                    if decoded_data.startswith("INICIO_DEL_PROFILE_PICTURE:"):
                        is_profile_picture = True
                        parts = decoded_data.split(":")
                        if len(parts) >= 4:
                            received_size = 0
                            file_name = parts[1]  # Nombre del archivo
                            file_size = int(parts[2])  # Tamaño del archivo
                            sender_nickname = parts[3]  # Nickname del remitente
                            logger.debug("*** Voy a recibir la foto de perfil de %s", sender_nickname)

                            # Crear un archivo temporal
                            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb') # No se borrará el archivo al cerrarlo
                            temp_file_path = temp_file.name
                            temp_file.close()  # Cerrar el archivo para que pueda ser escrito más tarde

                            # Dar permisos de lectura y escritura y evitar
                            # el error en Windows:
                            # Permission denied: 'C:\\Users\\Ahome\\AppData\\Local\\Temp\\tmpa05loims
                            os.chmod(temp_file_path, stat.S_IREAD | stat.S_IWRITE)

                            self.createProfilePicture.emit(sender_nickname, file_name, temp_file_path)  # Guardar path de la foto de perfil

                            # El temp_file_path es la ruta del archivo temporal
                            logger.debug("Temporary file path: %s", temp_file_path)
                            # Abrir el archivo para escritura
                            logger.debug("Datos recibidos\nNombre: %s\nTamaño: %s\nRemitente: %s", file_name, file_size, self.sender_nickname)
                            last_execution_time = time.time()


                except UnicodeDecodeError: # Si no se puede decodificar (entra en esta excepción), es un chunk binario
                    # Escribir el fragmento en el archivo temporal
                    with open(temp_file_path, 'ab') as temp_file:  # 'ab' para agregar en modo binario
                        temp_file.write(mensaje)

                    received_size += len(mensaje)
                    if received_size == 0 or file_size == 0:
                        percentage = 0
                    else:
                        percentage = int((received_size / file_size) * 100)


                    # Obtener el tiempo actual
                    current_time = time.time()

                    if is_profile_picture:
                        logger.debug("Fragmento recibido %s/%s bytes (%s%%)", received_size, file_size, percentage)


                    # Verificar si han pasado 30 segundos desde la última ejecución
                    if current_time - last_execution_time >= 40:
                        logger.debug("Fragmento recibido %s/%s bytes (%s%%)", received_size, file_size, percentage)
                        last_execution_time = current_time

                    #if percentage % 2 == 0:
                    #    logger.debug("Porcentaje procesado actualmente %s", percentage)
                    #    logger.debug("Fragmento/chunk recibido en process_files %s/%s bytes", received_size, file_size)

                    # si el archivo es menor a 300 mb, se actualiza cada 5%
                    if file_size < 300000000:
                        module = 5
                    else:
                        module = 2

                    if percentage % module == 0 and not is_profile_picture:
                        # esto llama a update_private_chat_files
                        self.fragmentReceived.emit(sender_nickname, file_name, temp_file_path, is_profile_picture, percentage)
                            
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error en CheckPrivateIncomingFilesWorker: {e}")
                break

    def stop(self):
        self.running = False


class NicknameWindow(QMainWindow):
    """ Ventana secundaria para ingresar el nickname. """
    user_connected = pyqtSignal()

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
        #self.chatroom_windows.update()
        MY_CHATROOM = self.chatroom_windows
        logger.debug("Chatroom creado para %s - %s", nickname, MY_CHATROOM)
        MY_NICKNAME = nickname
        self.user_connected.emit()
        self.close()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ventana Principal")
        self.setGeometry(100, 100, 300, 200)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        layout = QVBoxLayout(self.central_widget)

        self.btn_nickname = QPushButton("Iniciar sesión", self)
        self.nickname_window = NicknameWindow()
        self.btn_nickname.clicked.connect(self.ask_nickname_window)
        self.nickname_window.user_connected.connect(self.close_this_window)
        layout.addWidget(self.btn_nickname)

        self.btn_list_users = QPushButton("Cerrar aplicación", self)
        self.btn_list_users.clicked.connect(terminate_application)
        layout.addWidget(self.btn_list_users)

    def close_this_window(self):
        self.hide()

    def ask_nickname_window(self):
        self.nickname_window.show()

class UserInfo:
    def __init__(self, nickname: str):
        self.nickname = nickname
        self.profile_pic = None # bytes de la foto de perfil
        self.server_listening = None # servidor tcp para recibir mensajes de este usuario
        self.server_listening_files = None # servidor tcp para recibir archivos de este usuario
        self.client = None # cliente tcp para enviar mensajes a este usuario
        self.client_files = None # cliente tcp para enviar archivos a este usuario
        self.private_chat = None # ventana de chat privado con este usuario es de tipo QMainWindow
        self.visual_chat = None # es el area donde se ven los mensajes en la ventana de chat privado con este usuario
        self.entry_message = None # es el area para escribir mis mensajes en la ventana de chat privado con este usuario

class IncomingMessageOrchestrator(QObject):
    """ Esta clase crea un hilo que se enacarga de procesar los mensajes
    entrantes en el atributo incoming_messages_queue de un nodo multicast.
    """
    eventReceived = pyqtSignal(list, bool)
    
    def __init__(self, is_master, ip_multicast, port):
        super().__init__()
        self.port = port
        self.group = ip_multicast
        self.ttl = 10 # esto es para que los mensajes no se queden en la red
        self.create_socket()
        self.is_master = is_master
        self.running = True
        logger.info("IncomingMessageOrchestrator creado.")

    def create_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        operating_system = platform.system()
        logger.debug("Sistema operativo: %s", operating_system)

        if operating_system == "Windows":
            local_ip = get_ip_local()  # algo como 192.168.1.20
            self.sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(local_ip)
            )
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
            logger.debug("[ENVIADO AL ORCHESTRATOR] %s", msg)
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
        except Exception as e:
            logger.error("[ERROR] %s", e)

    def process_orchestrator(self):
        logger.debug("[MulticastReceiver] Iniciando proceso de escucha...")
        while self.running:
            try:
                logger.debug("[MulticastReceiver] Esperando mensaje...")
                data, addr = self.sock.recvfrom(1024)
                msg = data.decode('utf-8', errors='replace')
                logger.info("Recibido en IncomingMessageOrchestrator, msg: %s, addr: %s", msg, addr)
                if msg:
                    arguments = msg.split(":")
                    # Emitir la señal para que el hilo principal maneje la actualización de la GUI
                    # llama a handle_incoming_message
                    self.eventReceived.emit(arguments, self.is_master)
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

def handle_incoming_message(arguments, is_master):
    global MY_NICKNAME, USER_INFO_BY_NICKNAME, MY_CHATROOM

    action = arguments[0]
    sender_nickname = arguments[1]
    
    logger.debug("**handle_incoming_message** [Recibido en %s] %s de %s", MY_NICKNAME, action, sender_nickname)

    # Aquí se debe realizar la actualización de la GUI (en el hilo principal)
    if action == "CREATE_TCP_SERVER":
        recipient_nickname = arguments[2]
        if recipient_nickname == MY_NICKNAME:
            user_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
            if not user_info:
                USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                user_info = USER_INFO_BY_NICKNAME[sender_nickname]
            # NOTA: se llama al método desde el hilo principal, ya que este slot se ejecuta en el main thread.
            # TODO: separar la lógica de open_chat_in_recipient_side para que tenga la propia de files
            # y ese nuevo llamarlo desde CREATE_TCP_SERVER_FILES
            MY_CHATROOM.open_chat_in_recipient_side(recipient_nickname=sender_nickname, sender_nickname=recipient_nickname)
    elif action == "CREATE_TCP_CLIENT":
        recipient_nickname = arguments[2]
        if recipient_nickname == MY_NICKNAME:
            sender_ip = arguments[3]
            sender_port = int(arguments[4])
            user_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
            logger.debug("Ok, crear cliente para enviar mensajes escritos a %s", sender_nickname)
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
            #MY_CHATROOM.send_my_photo_profile_to_user()
    elif action == "UPDATE_USER_LIST":
        if sender_nickname != MY_NICKNAME and sender_nickname not in USER_INFO_BY_NICKNAME:
            USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
            MY_CHATROOM.update_user_list()
    elif action == "UPDATE_MY_PHOTO": # se recibe la foto de perfil de un usuario para actualizarla
        photo_bytes = arguments[2]
        if sender_nickname != MY_NICKNAME and sender_nickname in USER_INFO_BY_NICKNAME:
            MY_CHATROOM.update_photo_of_user(sender_nickname, photo_bytes)
    elif action == "SEND_GROUP_MESSAGE":
        message = arguments[2]
        if sender_nickname != MY_NICKNAME:
            MY_CHATROOM.update_group_chat(sender_nickname, message)
        else:
            MY_CHATROOM.update_group_chat("Tú", message)
    elif action == "CREATE_TCP_SERVER_FILES":
        # creo que no es necesario hacer nada aquí
        # tendria que separa la logica de open_chat_in_recipient_side
        pass
    elif action == "CREATE_TCP_CLIENT_FILES":
        recipient_nickname = arguments[2]
        if recipient_nickname == MY_NICKNAME:
            sender_ip = arguments[3]
            sender_port = int(arguments[4])
            user_info = USER_INFO_BY_NICKNAME.get(sender_nickname)
            logger.debug("Ok, crear cliente para enviar ACK/archivos a %s", sender_nickname)
            if not user_info:
                USER_INFO_BY_NICKNAME[sender_nickname] = UserInfo(sender_nickname)
                user_info = USER_INFO_BY_NICKNAME[sender_nickname]
            if user_info.client_files is None:
                logger.debug("Intentando crear cliente para enviar files a %s - %s: %s", sender_nickname, sender_ip, sender_port)
                client_socket_files = ClientTCP(f"client_of_{recipient_nickname}_to_send_files_to_{sender_nickname}", sender_ip, sender_port)
                user_info.client_files = client_socket_files

def main():
    # python send_files.py <server_type> <multicast_port>
    # Master: python3 send_files.py master 30001
    # Other: python3 send_files.py 30001

    # Configurar la ruta de las bibliotecas de VLC (solo en macOS)
    os.environ['VLC_PLUGIN_PATH'] = '/Applications/VLC.app/Contents/MacOS/plugins'
    os.environ['VLC_LIB_PATH'] = '/Applications/VLC.app/Contents/MacOS/lib'

    global MY_MULTICAST_PORT, WORKER_ORCHESTRATOR, THREAD_ORCHESTRATOR, MY_CHATROOM, IS_MASTER, SLAVE_NUMBER
    # Conectarse a un servidor multicast para comunicación interna o técnica entre nodos.
    # Esto actuará como orquestador de mensajes entre los nodos.
    ip_multicast = "224.0.0.0"
    is_master = True if len(sys.argv) > 1 and sys.argv[1] == "master" else False
    IS_MASTER = is_master
    SLAVE_NUMBER = sys.argv[1]
    MY_MULTICAST_PORT = int(sys.argv[2]) if len(sys.argv) >= 2 else 30000

    logger.debug("ip_multicast %s", ip_multicast)
    logger.debug("is_master %s", is_master)
    logger.debug("slave number %s", SLAVE_NUMBER)
    logger.debug("MY_MULTICAST_PORT %s", MY_MULTICAST_PORT)

    WORKER_ORCHESTRATOR = IncomingMessageOrchestrator(is_master, ip_multicast, MY_MULTICAST_PORT)
    logger.debug("Create QThread for IncomingMessageOrchestrator")
    THREAD_ORCHESTRATOR = QThread()
    logger.debug("Move IncomingMessageOrchestrator to QThread")
    WORKER_ORCHESTRATOR.moveToThread(THREAD_ORCHESTRATOR)
    # Conectar la señal del worker a un slot que se encargue de actualizar la GUI
    WORKER_ORCHESTRATOR.eventReceived.connect(handle_incoming_message)
    THREAD_ORCHESTRATOR.started.connect(WORKER_ORCHESTRATOR.process_orchestrator)
    THREAD_ORCHESTRATOR.start()

    app = QApplication(sys.argv)
    logger.debug("Creando ventana principal...")
    ventana = MainWindow()
    ventana.show()

    # Bucle principal; la ventana se ve
    ret = app.exec_()
    sys.exit(ret)

if __name__ == "__main__":
    main()