#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys
import signal
import multiprocessing
import errno
import os
import uuid
import threading
import time
os.environ["PYGAME_HIDE_SUPPORT_PROMPT"] = "1"
import pygame
from pygame.locals import *

# Dirección de grupo multicast (rango 224.0.0.0 - 239.255.255.255)
MCAST_GRP = '224.0.0.1'
MCAST_PORT = 30000
TTL = 1

def obtener_ip_local():
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

IP_LOCAL = obtener_ip_local()

class MulticastNode:
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
        """ Crear un socket multicast y lanza un hilo que recibe mensajes.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Después REUSEPORT (no siempre disponible)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind(('', self.port))

        group_bin = socket.inet_aton(self.group)
        mreq = struct.pack('4sL', group_bin, socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        ttl_bin = struct.pack('@i', TTL)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

        print(f"[MulticastReceiver] Escuchando en grupo {self.group}:{self.port} (TTL={self.ttl}).")
        #self.sock.settimeout(1.0)

        self.incoming_messages_queue = multiprocessing.Queue()
        self.stop_event = multiprocessing.Event()
        self.receiver_thread = multiprocessing.Process(
            target=self.receiver,
            args=(self.sock,self.incoming_messages_queue, self.group, self.port, self.stop_event),
            daemon=True
        )
        print(f"[MulticastReceiver] Iniciando receptor en {self.group}:{self.port}")
        self.receiver_thread.start()

    def stop(self):
        print("[MulticastReceiver] Deteniendo receptor...")
        self.stop_event.set()
        self.receiver_thread.terminate()
        self.receiver_thread.join()
        
    @staticmethod
    def receiver(sock, queue, group, port, stop_event):
        """ Hilo que recibe los mensajes multicast y los pone en una cola.
        """
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
        """ Envía un mensaje al grupo multicast.
        """
        try:
            data = msg.encode('utf-8')
            self.sock.sendto(data, (self.group, self.port))
            print(f"[ENVIADO] {msg}")
        except (KeyboardInterrupt, EOFError):
            print("\n[SALIENDO] Terminando nodo...")
            sys.exit(0)
        except Exception as e:
            print(f"[ERROR] {e}")

class PacmanNode:
    """ Esta clase va a crear un jugador de Pacman y podrá enviar
        mensajes al grupo multicast recibido por parametro
    """
    def __init__(self, player_uuid, player_name: str, node: MulticastNode):
        self.player_uuid = player_uuid
        self.player_name = player_name
        self.node = node

    def request_init_position(self):
        # TODO: Revisar que posición inicial no esté ocupada
        self.node.send(f"{self.player_uuid}:RQ_INIT_POSITION:{self.player_name}")

    def join_game(self, pos_init_x, pos_init_y, skin, player_uuid=None, name=None):
        if player_uuid is None:
            player_uuid = self.player_uuid
        if name is None:
            name = self.player_name
        self.node.send(f"{player_uuid}:JOIN:{name}:{pos_init_x}:{pos_init_y}:{skin}")

    def make_move(self, new_x, new_y):
        self.node.send(f"{self.player_uuid}:MOVE:{self.player_name}:{new_x}:{new_y}")

    def eat_block(self, x, y, block_id):
        self.node.send(f"{self.player_uuid}:EAT:{self.player_name}:{x}:{y}:{block_id}")

    def send_my_position_to(self, recipient_player_uuid, pos_x, pos_y, skin):
        self.node.send(f"{self.player_uuid}:LOAD_OTHER_PLAYERS:{recipient_player_uuid}:{self.player_name}:{pos_x}:{pos_y}:{skin}")

    def update_score(self, score):
        self.node.send(f"{self.player_uuid}:SCORE:{self.player_name}:{score}")

# --------------------------------------------------------------
#            Lógica para la interfaz gráfica del juego
# --------------------------------------------------------------

BLACK = (0,0,0)
WHITE = (255,255,255)
BLUE  = (0,0,255)
GREEN = (0,255,0)
RED   = (255,0,0)
PURPLE= (255,0,255)
YELLOW= (255,255,0)

class Wall(pygame.sprite.Sprite):
    def __init__(self, x, y, width, height, color=BLUE):
        super().__init__()
        self.image = pygame.Surface([width, height])
        self.image.fill(color)
        self.rect = self.image.get_rect()
        self.rect.x = x
        self.rect.y = y

class Block(pygame.sprite.Sprite):
    """
    Bolita que Pac-Man recolecta.
    """
    def __init__(self, color, width, height, block_id=None):
        super().__init__()
        self.image = pygame.Surface([width, height])
        self.image.fill(WHITE)
        self.image.set_colorkey(WHITE)
        pygame.draw.ellipse(self.image, color, [0,0,width,height])
        self.rect = self.image.get_rect()
        # Para identificarlo si necesitas removerlo luego
        self.block_id = block_id

class Player(pygame.sprite.Sprite):
    def __init__(self, x, y, filename="images/pacman.png", player_id="local"):
        super().__init__()
        self.image = pygame.image.load(filename).convert()
        self.image.set_colorkey(BLACK)  
        self.rect = self.image.get_rect()
        self.rect.x = x
        self.rect.y = y
        self.change_x = 0
        self.change_y = 0
        self.player_id = player_id

    def changespeed(self, x, y):
        self.change_x += x
        self.change_y += y

    def get_position(self):
        return self.rect.x, self.rect.y

    def set_position(self, x, y):
        self.rect.x = x
        self.rect.y = y

    def update(self, walls):
        old_x = self.rect.x
        old_y = self.rect.y

        # Mover en X
        self.rect.x += self.change_x
        wall_hit_list = pygame.sprite.spritecollide(self, walls, False)
        if wall_hit_list:
            self.rect.x = old_x

        # Mover en Y
        self.rect.y += self.change_y
        wall_hit_list = pygame.sprite.spritecollide(self, walls, False)
        if wall_hit_list:
            self.rect.y = old_y

class PacmanGame:
    def __init__(self, screen_size=(606,606)):
        pygame.init()
        self.screen = pygame.display.set_mode(screen_size)
        pygame.display.set_caption("Pacman Multicast")
        self.clock = pygame.time.Clock()

        # Música opcional
        try:
            pygame.mixer.init()
            pygame.mixer.music.load('pacman.mp3')
            pygame.mixer.music.play(1, 0.0)
        except Exception as e:
            print(f"[Audio] No se pudo cargar pacman.mp3: {e}")

        self.all_sprites_list = pygame.sprite.Group()
        self.wall_list = pygame.sprite.Group()
        self.block_list = pygame.sprite.Group()
        self.player_dict = {}

        self.font = pygame.font.SysFont("Arial", 24)
        self.score_dict = {}  # Guarda score por jugador_id

        self.setup_walls_and_blocks()
        self.player = None

    def setup_walls_and_blocks(self):
        walls_info = [ [0,0,6,600],
              [0,0,600,6],
              [0,600,606,6],
              [600,0,6,606],
              [300,0,6,66],
              [60,60,186,6],
              [360,60,186,6],
              [60,120,66,6],
              [60,120,6,126],
              [180,120,246,6],
              [300,120,6,66],
              [480,120,66,6],
              [540,120,6,126],
              [120,180,126,6],
              [120,180,6,126],
              [360,180,126,6],
              [480,180,6,126],
              [180,240,6,126],
              [180,360,246,6],
              [420,240,6,126],
              [240,240,42,6],
              [324,240,42,6],
              [240,240,6,66],
              [240,300,126,6],
              [360,240,6,66],
              [0,300,66,6],
              [540,300,66,6],
              [60,360,66,6],
              [60,360,6,186],
              [480,360,66,6],
              [540,360,6,186],
              [120,420,366,6],
              [120,420,6,66],
              [480,420,6,66],
              [180,480,246,6],
              [300,480,6,66],
              [120,540,126,6],
              [360,540,126,6]
            ]
        for w in walls_info:
            wall = Wall(w[0], w[1], w[2], w[3], BLUE)
            self.wall_list.add(wall)
            self.all_sprites_list.add(wall)

        # Crear bloques
        block_id_counter = 0
        for row in range(19):
            for col in range(19):
                # Ejemplo de exclusión
                if (row == 7 or row == 8) and (col in [8,9,10]):
                    continue
                block = Block(YELLOW, 4, 4, block_id=block_id_counter)
                block.rect.x = (30*col+6)+26
                block.rect.y = (30*row+6)+26
                wall_hits = pygame.sprite.spritecollide(block, self.wall_list, False)
                if not wall_hits:
                    self.block_list.add(block)
                    self.all_sprites_list.add(block)
                    block_id_counter += 1

    def add_player(self, player_name, player_uuid, x, y, skin):
        if player_uuid not in self.player_dict:
            self.player = Player(x, y, skin, player_uuid)
            self.player_dict[player_uuid] = self.player
            self.all_sprites_list.add(self.player)
            self.score_dict[player_uuid] = [player_name, 0]  # Iniciar score
        else:
            self.player_dict[player_uuid].set_position(x,y)

    def add_external_player(self, player_name, player_uuid, x, y, skin):
        if player_uuid not in self.player_dict:
            player = Player(x, y, skin, player_uuid)
            self.player_dict[player_uuid] = player
            self.all_sprites_list.add(player)
            self.score_dict[player_uuid] = [player_name, 0]  # Iniciar score
            print(f"[{player_name}] se ha unido al juego.")
        else:
            self.player_dict[player_uuid].set_position(x,y)

    def update_player_position(self, player_id, x, y):
        if player_id in self.player_dict:
            self.player_dict[player_id].set_position(x, y)

    def remove_block_by_id(self, block_id):
        to_remove = None
        for b in self.block_list:
            if getattr(b, 'block_id', None) == block_id:
                to_remove = b
                break
        if to_remove:
            self.block_list.remove(to_remove)
            self.all_sprites_list.remove(to_remove)

    def draw(self):
        self.screen.fill(BLACK)
        self.all_sprites_list.draw(self.screen)

        # Mostrar puntajes
        y_offset = 10
        for pid, info in self.score_dict.items():
            name = info[0]
            score = info[1]
            text = self.font.render(f"{name}: {score}", True, RED)
            self.screen.blit(text, (10, y_offset))
            y_offset += 24

        pygame.display.flip()

    def handle_local_input(self, node_player: PacmanNode):
        local_id = node_player.player_uuid
        
        local_player = self.player_dict.get(local_id)
        
        if not local_player:
            return True

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return False
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT:
                    local_player.changespeed(-30, 0)
                elif event.key == pygame.K_RIGHT:
                    local_player.changespeed(30, 0)
                elif event.key == pygame.K_UP:
                    local_player.changespeed(0, -30)
                elif event.key == pygame.K_DOWN:
                    local_player.changespeed(0, 30)
            if event.type == pygame.KEYUP:
                if event.key == pygame.K_LEFT:
                    local_player.changespeed(30, 0)
                elif event.key == pygame.K_RIGHT:
                    local_player.changespeed(-30, 0)
                elif event.key == pygame.K_UP:
                    local_player.changespeed(0, 30)
                elif event.key == pygame.K_DOWN:
                    local_player.changespeed(0, -30)

        old_x, old_y = local_player.rect.x, local_player.rect.y
        local_player.update(self.wall_list)
        new_x, new_y = local_player.rect.x, local_player.rect.y

        # Si cambió la posición, enviar MOVE a los demás nodos
        if new_x != old_x or new_y != old_y:
            node_player.make_move(new_x, new_y)

        # Revisar colisiones con bloques
        eaten_blocks = pygame.sprite.spritecollide(local_player, self.block_list, True)
        if eaten_blocks:
            # Actualizar score local
            self.score_dict[local_id][1] += len(eaten_blocks)
            # Avisar que se comieron
            node_player.update_score(self.score_dict[local_id][1])
            for block in eaten_blocks:
                node_player.eat_block(block.rect.x, block.rect.y, block.block_id)

        return True

    def stop(self):
        pygame.quit()

POS_X = None
POS_Y = None
SKIN = None

def process_incoming_messages(game: PacmanGame, node_player: PacmanNode, player_uuid, is_master=False):
    global POS_X, POS_Y, SKIN
    position_available = {}
    possibles_init_positions = [
        #(9, 14, "images/pacman.png"), master
        (9, 6, "images/pacman2.png"),
        (18, 0, "images/pacman3.png"),
        (0,0, "images/pacman4.png")
    ]

    while True:
        try:
            msg, addr = node_player.node.incoming_messages_queue.get()
            player_uuid_received = msg.split(":")[0]
            message = msg.split(":")[1:]
            action = message[0]

            if action == "JOIN":
                player_name = message[1]
                x, y, skin = int(message[2]), int(message[3]), message[4]
                if player_uuid_received == player_uuid:
                    print(f"Te has unido al juego como {player_name}")
                    POS_X, POS_Y, SKIN = x, y, skin
                else:
                    game.add_external_player(player_name, player_uuid_received, x, y, skin)
                    my_x, my_y = game.player.get_position()
                    print(f"Yo {node_player.player_name} Enviando mi posición a {player_name}, {my_x},{my_y}")
                    node_player.send_my_position_to(player_uuid_received, my_x, my_y, SKIN)
                continue

            if action == "RQ_INIT_POSITION" and is_master:
                position_available[player_uuid_received] = possibles_init_positions.pop(0)
                player_name = message[1]
                x, y, skin = position_available[player_uuid_received]
                x = (30*x)+12
                y = (30*y)+12
                print(f"Posicion asignada al jugador {player_name} en: ({x},{y})")
                node_player.join_game(x, y, skin, player_uuid_received, player_name)
                continue

            if action == "LOAD_OTHER_PLAYERS":
                recipient_player_uuid = message[1]
                if recipient_player_uuid != player_uuid:
                    continue
                player_name = message[2]
                pos_x, pos_y, skin = int(message[3]), int(message[4]), message[5]
                game.add_external_player(player_name,player_uuid_received, pos_x, pos_y, skin)
                continue

            if player_uuid_received == player_uuid:
                continue

            if action == "SCORE":
                player_name = message[1]
                score = int(message[2])
                game.score_dict[player_uuid_received][1] = score
                continue

            if action == "MOVE":
                player_name = message[1]
                x, y = int(message[2]), int(message[3])
                game.update_player_position(player_uuid_received, x, y)
                continue

            if action == "EAT":
                player_name = message[1]
                x, y = int(message[2]), int(message[3])
                block_id = int(message[4])
                game.remove_block_by_id(block_id)
                print(f"[{player_uuid_received}] comió un bloque en {x},{y}")
                continue
        except Exception as e:
            print(f"[ERROR] Procesando mensaje: {e}")

def main():
    global POS_X, POS_Y, SKIN
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda sig, frame: sys.exit(0))
    node_master = False
    if len(sys.argv) > 1 and sys.argv[1] == "master":
        node_master = True
    print(f"Node master: {node_master}")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else MCAST_PORT
    
    player_name = input("\nEscribe tu nombre y presiona Enter para unirte al juego: ")
    
    if not player_name:
        print("Debes escribir un nombre para unirte al juego.")
        sys.exit(1)

    player_uuid = str(uuid.uuid4())

    node = MulticastNode(MCAST_GRP, port, TTL)
    
    node_player = PacmanNode(player_uuid, player_name, node)

    game = PacmanGame()

    process_incoming_thread = threading.Thread(
        target=process_incoming_messages,
        args=(game, node_player, player_uuid, node_master),
        daemon=True
    )
    process_incoming_thread.start()

    if node_master:
        row = 9 # eje X
        col = 14 # eje Y
        POS_X = (30*row)+12
        POS_Y = (30*col)+12
        SKIN = "images/pacman.png"
    else:
        node_player.request_init_position()

    position_assigned = False
    running = True
    while running:
        try:
            if POS_X is None and POS_Y is None:
                continue
            if not position_assigned and POS_X is not None and POS_Y is not None and SKIN is not None:
                game.add_player(node_player.player_name, node_player.player_uuid, POS_X, POS_Y, SKIN)
                position_assigned = True
            game.draw()
            game.clock.tick(10)
            # loop de la interfaz gráfica
            running = game.handle_local_input(node_player=node_player)
        except KeyboardInterrupt:
            break

    node_player.node.stop()
    game.stop()

if __name__ == "__main__":
    main()
