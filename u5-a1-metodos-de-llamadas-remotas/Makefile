# Makefile

# Declaramos estas tareas como "phony" para evitar conflictos con archivos reales
.PHONY: start-win start clean

# Comando para Windows
start-win:
	python -m venv venv
	.\venv\Scripts\activate && python -m pip install --upgrade pip
	.\venv\Scripts\activate && pip install -r requirements.txt

# Comando para Linux / macOS
start:
	python3 -m venv venv
	. venv/bin/activate && python -m pip install --upgrade pip
	. venv/bin/activate && pip install -r requirements.txt

execute:
	. venv/bin/activate && python gato.py

execute-player-o:
	. venv/bin/activate && python gato.py false 127.0.0.1 30001 30002

# Limpieza (elimina la carpeta del entorno virtual en sistemas tipo Unix)
# En Windows, podrías usar: rmdir /S /Q venv
clean:
	rm -rf venv
