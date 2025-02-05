import sys
import socket
import threading
import json
import time
from PyQt5 import QtWidgets, QtCore, QtGui


class GameLogic:
    """
    Contiene el estado del juego del gato y funciones para verificar ganador o movimiento.
    """
    def __init__(self):
        # Representación del tablero en una lista de 9 elementos
        self.board = [None] * 9  
        self.current_player = 'X'  # Por convención, el jugador 1 usará 'X', jugador 2 usará 'O'
        self.winner = None

    def make_move(self, index):
        """
        Intenta realizar una jugada en la posición 'index' (0..8).
        Retorna True si la jugada es válida, False en caso contrario.
        """
        if self.board[index] is None and self.winner is None:
            self.board[index] = self.current_player
            # Después de marcar, revisamos si hay ganador
            if self.check_winner():
                self.winner = self.current_player
            else:
                # Alternar turno
                self.current_player = 'O' if self.current_player == 'X' else 'X'
            return True
        return False

    def check_winner(self):
        """
        Verifica si el jugador actual ha ganado.
        Retorna True si hay ganador, False en caso contrario.
        """
        # Posiciones ganadoras posibles
        win_positions = [
            (0,1,2), (3,4,5), (6,7,8),  # filas
            (0,3,6), (1,4,7), (2,5,8),  # columnas
            (0,4,8), (2,4,6)            # diagonales
        ]
        for (a,b,c) in win_positions:
            if (self.board[a] is not None and
                self.board[a] == self.board[b] == self.board[c]):
                return True
        return False

    def is_draw(self):
        """
        Determina si todas las casillas están llenas y no hay ganador.
        """
        return all(cell is not None for cell in self.board) and self.winner is None

    def reset_game(self):
        """
        Reinicia el estado del juego.
        """
        self.board = [None] * 9
        self.current_player = 'X'
        self.winner = None


class TicTacToeWindow(QtWidgets.QMainWindow):
    """
    Ventana principal del juego del gato con PyQt5, maneja la parte gráfica.
    """
    def __init__(self, is_player_one, peer_ip, local_port):
        super().__init__()
        self.my_symbol = 'X' if is_player_one else 'O'
        self.setWindowTitle(f"[Player {self.my_symbol}] Juego del Gato P2P")
        self.setFixedSize(300, 350)

        # Lógica del juego
        self.game_logic = GameLogic()

        # Identificador de si somos el jugador 1 o 2
        self.is_player_one = is_player_one  

        # Configurar la interfaz
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QtWidgets.QGridLayout(self.central_widget)

        # Crear botones para el tablero
        self.buttons = []
        for i in range(9):
            btn = QtWidgets.QPushButton("")
            btn.setFixedSize(80, 80)
            btn.setFont(QtGui.QFont("Arial", 20, QtGui.QFont.Bold))
            btn.clicked.connect(lambda _, idx=i: self.handle_button_click(idx))
            self.buttons.append(btn)
            self.layout.addWidget(btn, i // 3, i % 3)

        # Label de estado
        self.status_label = QtWidgets.QLabel("Esperando conexión...", self)
        self.layout.addWidget(self.status_label, 3, 0, 1, 3)

        # Sockets y comunicación
        self.peer_ip = peer_ip
        self.local_port = local_port

        # Diccionario de "acciones" RPC
        self.rpc_actions = {
            "make_move": self.rpc_make_move,
            "reset": self.rpc_reset
        }

        # Iniciar hilo de escucha
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.is_player_one:
            # Jugador 1 actúa como "servidor"
            self.start_server()
        else:
            # Jugador 2 se conecta al "servidor" (jugador 1)
            self.start_client()

        self.update_status_label()

    def update_status_label(self):
        """
        Actualiza la etiqueta de estado en función de la etapa del juego.
        """
        if self.game_logic.winner:
            self.status_label.setText(f"¡Jugador {self.game_logic.winner} ha ganado!")
        elif self.game_logic.is_draw():
            self.status_label.setText("¡Empate!")
        else:
            self.status_label.setText(f"Turno de {self.game_logic.current_player}")

    def handle_button_click(self, index):
        """
        Maneja el clic en un botón del tablero: 
        - Verifica si es nuestro turno.
        - Realiza la jugada local.
        - Envía el movimiento al oponente.
        """
        # Verificar si es nuestro turno
        if self.game_logic.current_player != self.my_symbol:
            return  # No hacemos nada si no es nuestro turno

        # Intentar hacer el movimiento
        if self.game_logic.make_move(index):
            # Actualizar la interfaz
            self.update_board()
            self.update_status_label()

            # Enviar movimiento al contrincante
            self.send_message({
                "action": "make_move",
                "index": index
            })

    def update_board(self):
        """
        Actualiza el texto de los botones de acuerdo al estado del board.
        """
        for i in range(9):
            if self.game_logic.board[i] is None:
                self.buttons[i].setText("")
            else:
                self.buttons[i].setText(self.game_logic.board[i])

    def rpc_make_move(self, data):
        """
        Acción remota: el contrincante hizo un movimiento en 'index'.
        """
        index = data.get("index")
        self.game_logic.make_move(index)
        self.update_board()
        self.update_status_label()

    def rpc_reset(self, data):
        """
        Acción remota para reiniciar la partida.
        """
        self.game_logic.reset_game()
        self.update_board()
        self.update_status_label()

    def start_server(self):
        """
        Inicia el socket en modo servidor (Jugador 1).
        """
        try:
            self.socket.bind((self.peer_ip, self.local_port))
            self.socket.listen(1)
            self.status_label.setText(f"Esperando conexión en puerto {self.local_port}...")
            time.sleep(1)
        except Exception as e:
            self.status_label.setText(f"Error iniciando servidor: {e}")
            return

        # Aceptar la conexión entrante en un hilo aparte
        threading.Thread(target=self.accept_connection, daemon=True).start()

    def accept_connection(self):
        """
        Acepta la conexión entrante y maneja los mensajes.
        """
        self.conn, addr = self.socket.accept()
        self.status_label.setText(f"Conectado con {addr}\n Turno de X")
        # Escuchar mensajes
        self.listen_thread = threading.Thread(target=self.listen_messages, daemon=True)
        self.listen_thread.start()

    def start_client(self):
        """
        Conecta al servidor (Jugador 2 se conecta a Jugador 1).
        """
        try:
            self.socket.connect((self.peer_ip, self.local_port))
            self.conn = self.socket
            self.status_label.setText(f"Conectado con {self.peer_ip}:{self.local_port}")
            # Hilo para escuchar mensajes
            self.listen_thread = threading.Thread(target=self.listen_messages, daemon=True)
            self.listen_thread.start()
        except Exception as e:
            self.status_label.setText(f"Error conectando a {self.peer_ip}:{self.local_port} - {e}")

    def listen_messages(self):
        """
        Hilo que escucha los mensajes entrantes y los procesa.
        """
        while True:
            try:
                data = self.conn.recv(1024)
                if not data:
                    break
                message = json.loads(data.decode('utf-8'))
                action = message.get("action")
                if action in self.rpc_actions:
                    # Ejecutar la función correspondiente en el hilo de la GUI
                    QtCore.QMetaObject.invokeMethod(
                        self,
                        "_handle_rpc_action",
                        QtCore.Qt.QueuedConnection,
                        QtCore.Q_ARG(dict, message)
                    )
            except:
                break

    @QtCore.pyqtSlot(dict)
    def _handle_rpc_action(self, message):
        """
        Slot interno que procesa la acción RPC en el hilo de la GUI.
        """
        action = message.get("action")
        self.rpc_actions[action](message)

    def send_message(self, msg):
        """
        Envía un mensaje JSON por el socket al contrincante.
        """
        try:
            if self.conn:
                self.conn.sendall(json.dumps(msg).encode('utf-8'))
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Ventana Principal")
        self.setGeometry(100, 100, 300, 200)

        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        self.btn_nickname = QtWidgets.QPushButton("Conectar jugador X", self)
        self.btn_nickname.clicked.connect(self.connect_player_x)
        layout.addWidget(self.btn_nickname)

        self.btn_list_users = QtWidgets.QPushButton("Conectar jugador O", self)
        self.btn_list_users.clicked.connect(self.connect_player_o)
        layout.addWidget(self.btn_list_users)

    def connect_player_x(self):
        is_player_one = True
        peer_ip = "127.0.0.1"
        local_port = 30002

        window = TicTacToeWindow(is_player_one, peer_ip, local_port)
        window.show()

    def connect_player_o(self):
        is_player_one = False
        peer_ip = "127.0.0.1"
        local_port = 30002

        window = TicTacToeWindow(is_player_one, peer_ip, local_port)
        window.show()


def main():
    app = QtWidgets.QApplication(sys.argv)
    ventana = MainWindow()
    ventana.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()