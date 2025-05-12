#!/usr/bin/env python3
# packet_sniffer.py - Un semplice analizzatore di pacchetti di rete con Python
# Esempio correlato alla tecnica T1040 (Network Sniffing) nel MITRE ATT&CK framework
# Richiede l'installazione di Scapy: pip install scapy

from scapy.all import *
import sys
import time
import socket
from datetime import datetime
import argparse
import signal
import threading

# Contatore globale dei pacchetti
packet_count = 0
start_time = 0
captured_packets = []
display_lock = threading.Lock()


# Funzione per gestire l'interruzione da tastiera
def signal_handler(sig, frame):
    print(f"\n\n[+] Cattura interrotta. Riepilogo:")
    duration = time.time() - start_time
    print(f"Durata: {duration:.2f} secondi")
    print(f"Pacchetti catturati: {packet_count}")

    # Statistiche dei protocolli
    protocols = {}
    for pkt in captured_packets:
        if IP in pkt:
            proto = pkt[IP].proto
            if proto == 6:  # TCP
                if proto not in protocols:
                    protocols[proto] = {"name": "TCP", "count": 0}
                protocols[proto]["count"] += 1
            elif proto == 17:  # UDP
                if proto not in protocols:
                    protocols[proto] = {"name": "UDP", "count": 0}
                protocols[proto]["count"] += 1
            elif proto == 1:  # ICMP
                if proto not in protocols:
                    protocols[proto] = {"name": "ICMP", "count": 0}
                protocols[proto]["count"] += 1
            else:
                if proto not in protocols:
                    protocols[proto] = {"name": f"Altro ({proto})", "count": 0}
                protocols[proto]["count"] += 1

    if protocols:
        print("\nDistribuzione dei protocolli:")
        for proto in protocols:
            percentage = (protocols[proto]["count"] / packet_count) * 100
            print(f"- {protocols[proto]['name']}: {protocols[proto]['count']} pacchetti ({percentage:.1f}%)")

    print(f"\n[*] Suggerimento: Per un'analisi più dettagliata, usa Wireshark")
    sys.exit(0)


# Registra il gestore di segnali per CTRL+C
signal.signal(signal.SIGINT, signal_handler)


# Funzione per estrapolare informazioni utili dal pacchetto
def get_packet_info(packet):
    info = {"src": "", "dst": "", "proto": "", "length": len(packet), "details": ""}

    if IP in packet:
        info["src"] = packet[IP].src
        info["dst"] = packet[IP].dst

        # TCP
        if packet.haslayer(TCP):
            info["proto"] = "TCP"
            info["sport"] = packet[TCP].sport
            info["dport"] = packet[TCP].dport

            # Controlla se è HTTP
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                info["service"] = "HTTP"
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', 'ignore')
                        # Estrai prime righe per l'anteprima
                        preview = payload.split('\n')[0][:50]
                        info["details"] = f"HTTP: {preview}..."
                    except:
                        pass

            # Controlla se è HTTPS
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                info["service"] = "HTTPS"
                info["details"] = "Traffico criptato"

            # Altri servizi comuni
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                info["service"] = "SSH"
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                info["service"] = "FTP"
            else:
                info["service"] = f"TCP/{packet[TCP].dport}" if packet[TCP].dport < 1024 else "TCP"

        # UDP
        elif packet.haslayer(UDP):
            info["proto"] = "UDP"
            info["sport"] = packet[UDP].sport
            info["dport"] = packet[UDP].dport

            # Controlla se è DNS
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                info["service"] = "DNS"
                if packet.haslayer(DNS):
                    if packet.getlayer(DNS).qr == 0:  # Query
                        try:
                            query = packet.getlayer(DNS).qd.qname.decode('utf-8')
                            info["details"] = f"Query: {query}"
                        except:
                            pass
                    else:  # Response
                        info["details"] = "Response"
            else:
                info["service"] = f"UDP/{packet[UDP].dport}" if packet[UDP].dport < 1024 else "UDP"

        # ICMP
        elif packet.haslayer(ICMP):
            info["proto"] = "ICMP"
            info["type"] = packet[ICMP].type
            if packet[ICMP].type == 8:
                info["details"] = "Echo Request (ping)"
            elif packet[ICMP].type == 0:
                info["details"] = "Echo Reply (ping)"
            else:
                info["details"] = f"Type: {packet[ICMP].type}"

    return info


# Funzione di callback chiamata per ogni pacchetto intercettato
def packet_callback(packet):
    global packet_count, captured_packets
    packet_count += 1

    # Aggiungi pacchetto alla lista per l'analisi
    if len(captured_packets) < 1000:  # Limita la memoria utilizzata
        captured_packets.append(packet)

    # Estrai informazioni
    info = get_packet_info(packet)

    # Formatta l'output
    with display_lock:
        print(f"[{packet_count}] ", end="")

        if "service" in info:
            print(f"{info['service']} ", end="")

        print(f"{info['src']} → {info['dst']} ", end="")

        if "sport" in info and "dport" in info:
            print(f"Porte: {info['sport']} → {info['dport']} ", end="")

        print(f"[{info['proto']}] {info['length']} bytes")

        if info.get("details"):
            print(f"  Dettagli: {info['details']}")


# Funzione principale
def main():
    global start_time

    # Analizza gli argomenti della riga di comando
    parser = argparse.ArgumentParser(description="Packet Sniffer Python - Per uso educativo")
    parser.add_argument("-i", "--interface", help="Interfaccia di rete da utilizzare")
    parser.add_argument("-c", "--count", type=int, default=0, help="Numero di pacchetti da catturare (0 = infinito)")
    parser.add_argument("-f", "--filter", default="", help="Filtro BPF (es. 'tcp port 80' o 'icmp')")
    args = parser.parse_args()

    print("\n===== PACKET SNIFFER PYTHON - USO EDUCATIVO =====")
    print("Basato sulla tecnica T1040 - Network Sniffing")
    print("MITRE ATT&CK Framework - https://attack.mitre.org/techniques/T1040/")
    print("=================================================\n")

    # Mostra configurazione
    print(f"[*] Configurazione:")
    if args.interface:
        print(f"Interfaccia: {args.interface}")
    else:
        print("Interfaccia: tutte le disponibili")

    if args.filter:
        print(f"Filtro: {args.filter}")
    else:
        print("Filtro: nessuno (tutto il traffico)")

    if args.count > 0:
        print(f"Limite pacchetti: {args.count}")
    else:
        print("Limite pacchetti: nessuno (infinito)")

    print(f"\n[+] Avvio cattura pacchetti... (Premi CTRL+C per terminare)")
    print("-" * 70)

    # Registra il momento di inizio
    start_time = time.time()

    # Avvia lo sniffing
    try:
        if args.count > 0:
            if args.interface:
                sniff(iface=args.interface, prn=packet_callback, filter=args.filter, count=args.count)
            else:
                sniff(prn=packet_callback, filter=args.filter, count=args.count)
        else:
            if args.interface:
                sniff(iface=args.interface, prn=packet_callback, filter=args.filter, store=0)
            else:
                sniff(prn=packet_callback, filter=args.filter, store=0)
    except PermissionError:
        print(f"\n[!] Errore: Permessi insufficienti. Esegui lo script con privilegi amministrativi (sudo).")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Errore: {str(e)}")
        sys.exit(1)

    # Riepilogo (in caso di count specificato)
    duration = time.time() - start_time
    print(f"\n[+] Cattura completata. Riepilogo:")
    print(f"Durata: {duration:.2f} secondi")
    print(f"Pacchetti catturati: {packet_count}")


# Esecuzione come script standalone
if __name__ == "__main__":
    # Controllo dei permessi elevati (necessari per lo sniffing)
    if os.geteuid() != 0 and sys.platform.startswith('linux'):
        print(f"[!] Questo script deve essere eseguito con privilegi amministrativi.")
        print(f"    Eseguilo con: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    main()