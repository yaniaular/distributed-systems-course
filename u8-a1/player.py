from PyQt5.QtWidgets import QWidget, QFrame, QSlider, QHBoxLayout, QPushButton, QVBoxLayout, QLabel
import vlc
import time
import sys
from PyQt5.QtCore import Qt, QTimer


class Player(QWidget):
    """Un reproductor de video usando VLC y Qt."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.instance = vlc.Instance()
        self.mediaplayer = self.instance.media_player_new()
        self.createUI()
        self.isPaused = False

    def createUI(self):
        """Configurar la interfaz de usuario."""
        self.videoframe = QFrame(self)
        self.videoframe.setStyleSheet("background-color: black;")
        
        self.positionslider = QSlider(Qt.Horizontal, self)
        self.positionslider.setToolTip("Position")
        self.positionslider.setMaximum(1000)
        self.positionslider.sliderMoved.connect(self.setPosition)

        # Etiqueta para mostrar el tiempo
        #self.time_label = QLabel("00:00 / 00:00", self)
        #self.time_label.setAlignment(Qt.AlignCenter)

        self.playbutton = QPushButton("Play", self)
        self.stopbutton = QPushButton("Stop", self)

        # Layout
        hbox = QHBoxLayout()
        hbox.addWidget(self.playbutton)
        hbox.addWidget(self.stopbutton)

        vbox = QVBoxLayout()
        vbox.addWidget(self.videoframe)
        vbox.addWidget(self.positionslider)
        #vbox.addWidget(self.time_label)  # Agregar la etiqueta de tiempo
        vbox.addLayout(hbox)

        self.setLayout(vbox)

        # Conectar señales
        self.playbutton.clicked.connect(self.PlayPause)
        self.stopbutton.clicked.connect(self.Stop)

        self.timer = QTimer(self)
        self.timer.setInterval(200)
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
        """Establecer la posición."""
        self.mediaplayer.set_position(position / 1000.0)

    def OpenFile(self, filename):
        """Abrir un archivo de video."""
        # create the media
        #if sys.version < '3':
        #    filename = str(filename)

        self.media = self.instance.media_new(filename)
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

        time.sleep(1)
        # Obtener la duración del video en milisegundos
        duration_ms = self.mediaplayer.get_length()
        seconds = duration_ms / 1000  # Convertir milisegundos a segundos
        minutes = seconds / 60        # Convertir segundos a minutos
        duration_minutes = round(minutes, 2)
        print("**** Current time of the video:", duration_minutes)

        self.PlayPause()

    def format_time(self, milliseconds):
        """Formatear el tiempo en minutos y segundos."""
        seconds = milliseconds // 1000
        minutes = seconds // 60
        seconds %= 60
        return f"{minutes:02}:{seconds:02}"

    def updateUI(self):
        """updates the user interface"""
        # setting the slider to the desired position
        self.positionslider.setValue(int(self.mediaplayer.get_position() * 1000))

        if self.mediaplayer.is_playing():
            pass

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


        # Aceptar el evento de cierre
        event.accept()