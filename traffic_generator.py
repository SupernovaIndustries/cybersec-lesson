#!/usr/bin/env python3
# traffic_generator.py - Genera traffico di rete per test e dimostrazioni
# Utile per testare il packet_sniffer.py in ambiente controllato

import socket
import sys
import time
import random
import argparse
import threading
import requests
from scapy.all import *


# Funzione per generare richieste HTTP
def generate_http_traffic(target, port=80, count=5, interval=1):
    print(f"[*] Generazione di {count} richieste HTTP verso {target}:{port}")

    for i in range(count):
        try:
            url = f"http://{target}:{port}"
            print(f"[+] Invio richiesta HTTP #{i + 1} a {url}")
            response = requests.get(url, timeout=5)
            print(f"    Risposta: HTTP {response.status_code}")
        except Exception as e:
            print(f"[!] Errore: {str(e)}")

        time.sleep(interval)


# Funzione per generare ping (ICMP)
def generate_ping_traffic(target, count=5, interval=1):
    print(f"[*] Generazione di {count} ping ICMP verso {target}")

    for i in range(count):
        try:
            print(f"[+] Invio ICMP Echo Request #{i + 1} a {target}")
            packet = IP(dst=target) / ICMP()
            reply = sr1(packet, timeout=2, verbose=0)

            if reply:
                print(f"    Risposta ricevuta da {reply.src}")
            else:
                print(f"    Nessuna risposta ricevuta")
        except Exception as e:
            print(f"[!] Errore: {str(e)}")

        time.sleep(interval)


# Funzione per generare traffico DNS
def generate_dns_traffic(count=5, interval=1):
    domains = ["example.com", "google.com", "github.com", "wikipedia.org", "python.org"]

    print(f"[*] Generazione di {count} query DNS")

    for i in range(count):
        domain = random.choice(domains)
        try:
            print(f"[+] Invio query DNS #{i + 1} per {domain}")
            result = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)), timeout=2, verbose=0)

            if result:
                print(f"    Risposta ricevuta con {result[DNS].ancount} record")
            else:
                print(f"    Nessuna risposta ricevuta")
        except Exception as e:
            print(f"[!] Errore: {str(e)}")

        time.sleep(interval)


# Funzione per generare traffico TCP su porte specifiche
def generate_tcp_traffic(target, ports=[80, 443, 22, 21], count=5, interval=1):
    print(f"[*] Generazione di {count} connessioni TCP verso {target}")

    for i in range(count):
        port = random.choice(ports)
        try:
            print(f"[+] Tentativo di connessione TCP #{i + 1} a {target}:{port}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex((target, port))

            if result == 0:
                print(f"    Connessione stabilita con {target}:{port}")
                s.close()
            else:
                print(f"    Porta {port} chiusa o filtrata")
        except Exception as e:
            print(f"[!] Errore: {str(e)}")

        time.sleep(interval)


# Funzione per inviare un pacchetto UDP personalizzato
def generate_udp_traffic(target, ports=[53, 123, 161, 1900], count=5, interval=1):
    print(f"[*] Generazione di {count} pacchetti UDP verso {target}")

    for i in range(count):
        port = random.choice(ports)
        try:
            data = b"PYTHONTRAFFICGENERATOR"
            print(f"[+] Invio pacchetto UDP #{i + 1} a {target}:{port}")

            packet = IP(dst=target) / UDP(dport=port) / Raw(load=data)
            send(packet, verbose=0)
            print(f"    Pacchetto UDP inviato a {target}:{port}")
        except Exception as e:
            print(f"[!] Errore: {str(e)}")

        time.sleep(interval)


# Funzione principale
def main():
    parser = argparse.ArgumentParser(description="Generatore di Traffico di Rete per Test")
    parser.add_argument("-t", "--target", required=True, help="Indirizzo IP o hostname del target")
    parser.add_argument("--http", action="store_true", help="Genera traffico HTTP")
    parser.add_argument("--ping", action="store_true", help="Genera traffico ICMP (ping)")
    parser.add_argument("--dns", action="store_true", help="Genera query DNS")
    parser.add_argument("--tcp", action="store_true", help="Genera connessioni TCP")
    parser.add_argument("--udp", action="store_true", help="Genera pacchetti UDP")
    parser.add_argument("--all", action="store_true", help="Genera tutti i tipi di traffico")
    parser.add_argument("-c", "--count", type=int, default=5, help="Numero di pacchetti per tipo (default: 5)")
    parser.add_argument("-i", "--interval", type=float, default=1,
                        help="Intervallo tra i pacchetti in secondi (default: 1)")
    args = parser.parse_args()

    print("\n===== GENERATORE DI TRAFFICO - USO EDUCATIVO =====")
    print("Utile per testare packet_sniffer.py e Wireshark")
    print("=================================================\n")

    # Se non è specificato alcun tipo di traffico o è specificato --all, genera tutto
    generate_all = args.all or not (args.http or args.ping or args.dns or args.tcp or args.udp)

    # Lista di thread
    threads = []

    # Genera traffico HTTP
    if args.http or generate_all:
        http_thread = threading.Thread(target=generate_http_traffic,
                                       args=(args.target, 80, args.count, args.interval))
        threads.append(http_thread)

    # Genera ping
    if args.ping or generate_all:
        ping_thread = threading.Thread(target=generate_ping_traffic,
                                       args=(args.target, args.count, args.interval))
        threads.append(ping_thread)

    # Genera query DNS
    if args.dns or generate_all:
        dns_thread = threading.Thread(target=generate_dns_traffic,
                                      args=(args.count, args.interval))
        threads.append(dns_thread)

    # Genera connessioni TCP
    if args.tcp or generate_all:
        tcp_thread = threading.Thread(target=generate_tcp_traffic,
                                      args=(args.target, [80, 443, 22, 21], args.count, args.interval))
        threads.append(tcp_thread)

    # Genera pacchetti UDP
    if args.udp or generate_all:
        udp_thread = threading.Thread(target=generate_udp_traffic,
                                      args=(args.target, [53, 123, 161, 1900], args.count, args.interval))
        threads.append(udp_thread)

    # Avvia tutti i thread
    for thread in threads:
        thread.start()

    # Attendi il completamento di tutti i thread
    for thread in threads:
        thread.join()

    print(f"\n[+] Generazione di traffico completata!")


# Esecuzione come script standalone
if __name__ == "__main__":
    # Controllo dei permessi elevati (per scapy)
    if os.geteuid() != 0 and sys.platform.startswith('linux'):
        print(f"[!] Questo script deve essere eseguito con privilegi amministrativi.")
        print(f"    Eseguilo con: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    main()