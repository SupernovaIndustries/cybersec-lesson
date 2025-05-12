#!/usr/bin/env python3
# port_scanner.py - Un semplice scanner di porte con Python
# Esempio correlato alla tecnica T1046 (Network Service Discovery) nel MITRE ATT&CK framework

import socket
import sys
import time
import threading
from datetime import datetime


# Banner di avvio
def print_banner():
    print("-" * 60)
    print("SCANNER DI PORTE PYTHON - USO EDUCATIVO")
    print("Basato sulla tecnica T1046 - Network Service Discovery")
    print("MITRE ATT&CK Framework - https://attack.mitre.org/techniques/T1046/")
    print("-" * 60)


# Funzione per controllare se una porta è aperta
def check_port(target, port, timeout=1):
    try:
        # Crea un oggetto socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        # Tenta di connettersi alla porta
        result = s.connect_ex((target, port))

        # Se il risultato è 0, la porta è aperta
        if result == 0:
            try:
                # Tenta di identificare il servizio
                service = socket.getservbyport(port)
            except:
                service = "sconosciuto"
            print(f"Porta {port}: \t APERTA \t Servizio: {service}")

        s.close()
        return result == 0
    except KeyboardInterrupt:
        print("\nScansione interrotta dall'utente.")
        sys.exit()
    except socket.gaierror:
        print("Errore: Il nome host non può essere risolto.")
        sys.exit()
    except socket.error:
        print(f"Errore di connessione alla porta {port}")
        return False


# Funzione principale di scansione
def port_scan(target, ports, num_threads=100):
    print_banner()

    # Risoluzione DNS
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Scansione del target: {target} ({target_ip})")
    except socket.gaierror:
        print("Errore: Il nome host non può essere risolto.")
        sys.exit()

    # Timestamp di inizio
    start_time = time.time()
    print(f"Scansione iniziata: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    # Usa threading per velocizzare la scansione
    threads = []
    open_ports = []

    # Crea thread per ogni porta
    for port in ports:
        # Limita il numero di thread attivi
        while threading.active_count() > num_threads:
            time.sleep(0.1)

        thread = threading.Thread(target=lambda p=port:
        open_ports.append(p) if check_port(target, p) else None)
        thread.daemon = True
        threads.append(thread)
        thread.start()

    # Attendi il completamento di tutti i thread
    for thread in threads:
        thread.join()

    # Timestamp di fine
    end_time = time.time()
    duration = end_time - start_time

    # Riepilogo
    print("-" * 60)
    print(f"Scansione completata in {duration:.2f} secondi")
    print(f"Porte aperte trovate: {len(open_ports)}")
    print("-" * 60)

    return open_ports


# Esecuzione come script standalone
if __name__ == "__main__":
    # Ottieni l'indirizzo del target dagli argomenti della riga di comando o chiedi all'utente
    if len(sys.argv) >= 2:
        target = sys.argv[1]
    else:
        target = input("Inserisci l'indirizzo IP o hostname del target: ")

    print("\nScegli un'opzione di scansione:")
    print("1) Porte comuni (1-1024)")
    print("2) Tutte le porte (1-65535)")
    print("3) Porte personalizzate")
    choice = input("Opzione (1-3): ")

    if choice == '1':
        ports = range(1, 1025)
    elif choice == '2':
        ports = range(1, 65536)
    elif choice == '3':
        port_range = input("Inserisci le porte da scansionare (es. 80,443,8080 o 1-1024): ")
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(p.strip()) for p in port_range.split(',')]
    else:
        print("Opzione non valida. Utilizzo delle porte comuni (1-1024).")
        ports = range(1, 1025)

    # Esegui la scansione
    open_ports = port_scan(target, ports)