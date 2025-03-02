from PyQt5.QtWidgets import QWidget, QFrame, QSlider, QHBoxLayout, QPushButton, QVBoxLayout, QLabel
import vlc
import time
import sys
from PyQt5.QtCore import Qt, QTimer, pyqtSignal


class Player(QWidget):
    window_closed = pyqtSignal()

    """Un reproductor de video usando VLC y Qt."""
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.instance = vlc.Instance()
        self.mediaplayer = self.instance.media_player_new()
        self.createUI()
        self.isPaused = False
        self.file_path = file_path

    def createUI(self):
        """Configurar la interfaz de usuario."""
        self.videoframe = QFrame(self)
        self.videoframe.setStyleSheet("background-color: black;")
        
        self.positionslider = QSlider(Qt.Horizontal, self)
        self.positionslider.setToolTip("Position")
        self.positionslider.setMaximum(1000)
        self.positionslider.sliderMoved.connect(self.setPosition)
        #self.positionslider.sliderReleased.connect(self.setPosition)

        # Etiqueta para mostrar el tiempo
        self.time_label = QLabel("00:00 / 00:00", self)
        self.time_label.setStyleSheet("""
            font-size: 10px;  /* Tamaño de la fuente */
            padding: 2px;    /* Padding interno reducido */
            margin: 0px;      /* Margen externo reducido */
        """)
        # Forzar un tamaño mínimo y máximo para el QLabel
        self.time_label.setMinimumSize(50, 15)  # Ancho mínimo de 100px, alto mínimo de 30px
        self.time_label.setMaximumSize(100, 20)  # Ancho máximo de 200px, alto máximo de 40px
        self.time_label.setAlignment(Qt.AlignRight)  # Alinear el texto a la derecha

        self.playbutton = QPushButton("Play", self)
        self.stopbutton = QPushButton("Stop", self)
        self.updatefragmentbutton = QPushButton("Update fragments", self)

        # Layout
        hbox = QHBoxLayout()
        hbox.addWidget(self.playbutton)
        hbox.addWidget(self.stopbutton)
        hbox.addWidget(self.updatefragmentbutton)

        self.vbox = QVBoxLayout()
        self.vbox.addWidget(self.videoframe)
        self.vbox.addWidget(self.positionslider)
        self.vbox.addWidget(self.time_label)
        self.vbox.addLayout(hbox)

        self.setLayout(self.vbox)

        # Conectar señales
        self.playbutton.clicked.connect(self.PlayPause)
        self.stopbutton.clicked.connect(self.Stop)
        self.updatefragmentbutton.clicked.connect(self.updateFragment)

        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.updateUI)

    def PlayPause(self):
        """Alternar entre play/pause."""
        if self.mediaplayer.is_playing():
            self.mediaplayer.pause()
            self.playbutton.setText("Play")
            self.isPaused = True
        else:
            if self.mediaplayer.play() == -1:
                return
            self.mediaplayer.play()
            self.playbutton.setText("Pause")
            self.isPaused = False
            self.timer.start()

    def Stop(self):
        """Detener la reproducción."""
        self.mediaplayer.stop()
        self.playbutton.setText("Play")
        self.timer.stop()

    def setPosition(self, position):
        if self.mediaplayer.is_playing():
            # Obtener la posición del slider (0-1000) y convertirla a un valor entre 0 y 1
            position = self.positionslider.value()
            vlc_position = position / 1000.0

            # Establecer la posición en VLC
            try:
                self.mediaplayer.set_position(vlc_position)
            except Exception as e:
                print(f"Error al establecer la posición: {e}")

    def ms_to_time_str(self, milliseconds):
        """Convertir milisegundos a una cadena en formato minutos:segundos."""
        if milliseconds == -1:
            return "00:00"

        seconds = milliseconds // 1000
        minutes = seconds // 60
        seconds = seconds % 60
        return f"{minutes:02}:{seconds:02}"

    def updateTimeLabel(self):
        """Actualizar el tiempo en el QLabel."""
        current_time = self.mediaplayer.get_time()  # Tiempo actual en milisegundos
        total_time = self.mediaplayer.get_length()  # Duración total en milisegundos

        # Convertir a formato minutos:segundos
        current_time_str = self.ms_to_time_str(current_time)
        total_time_str = self.ms_to_time_str(total_time)

        # Actualizar el QLabel
        self.time_label.setText(f"{current_time_str} / {total_time_str}")

    def updateSlider(self):
        """Actualizar el tiempo en el QLabel."""
        current_time = self.mediaplayer.get_time()  # Tiempo actual en milisegundos
        total_time = self.mediaplayer.get_length()  # Duración total en milisegundos

        # Actualizar el QSlider
        if total_time > 0:
            position = current_time / total_time
            self.positionslider.setValue(int(position * 1000))

    def OpenFile(self):
        """Abrir un archivo de video."""
        self.media = self.instance.media_new(self.file_path)
        self.mediaplayer.set_media(self.media)

        # parse the metadata of the file
        self.media.parse()
        # set the title of the track as window title
        self.setWindowTitle(self.media.get_meta(0))

        # the media player has to be 'connected' to the QFrame
        # (otherwise a video would be displayed in it's own window)
        # this is platform specific!
        # you have to give the id of the QFrame (or similar object) to
        # vlc, different platforms have different functions for this
        if sys.platform.startswith('linux'): # for Linux using the X Server
            self.mediaplayer.set_xwindow(self.videoframe.winId())
        elif sys.platform == "win32": # for Windows
            self.mediaplayer.set_hwnd(self.videoframe.winId())
        if sys.platform == "darwin": # for MacOS
            self.mediaplayer.set_nsobject(int(self.videoframe.winId()))

        self.PlayPause()

        # Esperar a que el video se cargue completamente para revisar la duracion
        while self.mediaplayer.get_state() != vlc.State.Playing:
            time.sleep(0.1)  # Esperar hasta que el video esté en estado "Playing"

        self.updateTimeLabel()
        self.updateSlider()

    def updateFragment(self):
        # Detener la reproducción actual
        self.mediaplayer.stop()

        # Cargar el nuevo fragmento
        self.media = self.instance.media_new(self.file_path)
        self.mediaplayer.set_media(self.media)
        self.media.parse()

        self.PlayPause()

        # Esperar a que el video se cargue completamente para revisar la duracion
        while self.mediaplayer.get_state() != vlc.State.Playing:
            time.sleep(0.1)  # Esperar hasta que el video esté en estado "Playing"

        self.updateTimeLabel()
        self.updateSlider()


    def updateUI(self):
        """updates the user interface"""
        # setting the slider to the desired position
        # self.positionslider.setValue(int(self.mediaplayer.get_position() * 1000))

        if self.mediaplayer.is_playing():
            self.updateTimeLabel()
            self.updateSlider()
        else:
            # no need to call this function if nothing is played
            self.timer.stop()
            if not self.isPaused:
                # after the video finished, the play button stills shows
                # "Pause", not the desired behavior of a media player
                # this will fix it
                self.Stop()

    def closeEvent(self, event):
        """Manejar el cierre del widget."""
        # Detener y liberar el reproductor de VLC
        if self.mediaplayer.is_playing():
            self.mediaplayer.pause()
            self.isPaused = True
        self.mediaplayer.stop()
        self.mediaplayer.release()
        self.timer.stop()
        self.instance.release()

        # Emitir la señal personalizada
        self.window_closed.emit()
        # Aceptar el evento de cierre
        event.accept()