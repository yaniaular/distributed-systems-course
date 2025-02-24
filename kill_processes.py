import psutil

# Puertos objetivo
PUERTOS_OBJETIVO = {30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009, 40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009}

def matar_procesos_por_puertos(puertos):
    procesos_matados = set()

    # Recorremos todas las conexiones de red activas
    for conn in psutil.net_connections():
        # Verificamos que la conexión tenga una dirección local y que el puerto esté en la lista
        if conn.laddr and conn.laddr.port in puertos:
            pid = conn.pid
            if pid is None:
                continue  # Algunos procesos pueden no tener pid asociado
            if pid not in procesos_matados:
                try:
                    proceso = psutil.Process(pid)
                    print(f"Matando proceso {pid} ({proceso.name()}) que usa el puerto {conn.laddr.port}")
                    proceso.kill()  # Enviar señal de terminación
                    procesos_matados.add(pid)
                except Exception as e:
                    print(f"No se pudo matar el proceso {pid}: {e}")
    
    if not procesos_matados:
        print("No se encontraron procesos usando los puertos:", puertos)
    else:
        print("Procesos finalizados:", procesos_matados)


# Lista de fragmentos (keywords) a buscar en la línea de comando de los procesos
KEYWORDS = [
    "from multiprocessing.resource_tracker import main;main(8)",
    "from multiprocessing.spawn import spawn_main",
    "chat_encriptado.py"
]

def kill_processes_by_keywords(keywords):
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Unir los argumentos del proceso en una cadena
            cmdline = " ".join(proc.info.get('cmdline') or [])
            # Revisar si alguno de los keywords se encuentra en la línea de comando
            for keyword in keywords:
                if keyword in cmdline:
                    print(f"Matando proceso {proc.pid} ({proc.info.get('name')}) -> CMD: {cmdline}")
                    proc.kill()
                    break  # Evitar matar varias veces el mismo proceso
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

if __name__ == "__main__":
    matar_procesos_por_puertos(PUERTOS_OBJETIVO)
    kill_processes_by_keywords(KEYWORDS)

