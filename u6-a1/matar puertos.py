import psutil

# Puertos objetivo
PUERTOS_OBJETIVO = {30000, 30001}

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

if __name__ == "__main__":
    matar_procesos_por_puertos(PUERTOS_OBJETIVO)
