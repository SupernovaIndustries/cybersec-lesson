#!/usr/bin/env python3
# secure_comms.py - Dimostra comunicazioni sicure vs non sicure
# Contiene sia un client che un server TCP che possono comunicare in chiaro o con crittografia

import socket
import threading
import argparse
import sys
import os
import time
import random
import string
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


# Classe per le funzioni crittografiche
class CryptoUtils:
    @staticmethod
    def generate_key_pair():
        # Genera una coppia di chiavi RSA (pubblica e privata)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key):
        # Serializza la chiave pubblica per il trasferimento
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    @staticmethod
    def deserialize_public_key(pem_data):
        # Deserializza la chiave pubblica
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        return public_key

    @staticmethod
    def generate_aes_key():
        # Genera una chiave AES casuale
        return os.urandom(32)  # 256 bit

    @staticmethod
    def encrypt_with_public_key(data, public_key):
        # Cripta i dati con la chiave pubblica RSA
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    @staticmethod
    def decrypt_with_private_key(encrypted_data, private_key):
        # Decripta i dati con la chiave privata RSA
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    @staticmethod
    def encrypt_with_aes(data, key):
        # Cripta i dati con AES-GCM
        iv = os.urandom(12)  # 96 bit per GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        # Restituisce IV, tag di autenticazione e testo cifrato
        return iv + encryptor.tag + ciphertext

    @staticmethod
    def decrypt_with_aes(encrypted_data, key):
        # Decripta i dati con AES-GCM
        iv = encrypted_data[:12]  # 96 bit per GCM
        tag = encrypted_data[12:28]  # 128 bit per il tag
        ciphertext = encrypted_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


# Classe per il server TCP
class SecureTCPServer:
    def __init__(self, host, port, use_encryption=True):
        self.host = host
        self.port = port
        self.use_encryption = use_encryption
        self.server_socket = None
        self.clients = {}  # {client_address: {"socket": socket, "aes_key": key}}
        self.running = False

        # Genera chiavi RSA per il server
        if self.use_encryption:
            self.private_key, self.public_key = CryptoUtils.generate_key_pair()
            self.public_key_pem = CryptoUtils.serialize_public_key(self.public_key)

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print(f"[+] Server avviato su {self.host}:{self.port}")
            if self.use_encryption:
                print(f"[+] Crittografia attivata (modalità sicura)")
            else:
                print(f"[!] Crittografia disattivata (modalità non sicura)")

            # Inizia ad accettare connessioni
            self.accept_connections()

        except Exception as e:
            print(f"[!] Errore nell'avvio del server: {str(e)}")

    def accept_connections(self):
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()

                print(f"[*] Nuova connessione da {address[0]}:{address[1]}")

                # Gestisci il client in un thread separato
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()

            except Exception as e:
                if self.running:
                    print(f"[!] Errore nell'accettare connessioni: {str(e)}")

    def handle_client(self, client_socket, address):
        try:
            client_info = {"socket": client_socket}
            self.clients[address] = client_info

            if self.use_encryption:
                # 1. Invia la chiave pubblica del server al client
                client_socket.sendall(self.public_key_pem)
                print(f"[*] Inviata chiave pubblica a {address[0]}:{address[1]}")

                # 2. Ricevi la chiave AES criptata dal client
                encrypted_aes_key = client_socket.recv(4096)
                aes_key = CryptoUtils.decrypt_with_private_key(encrypted_aes_key, self.private_key)
                client_info["aes_key"] = aes_key
                print(f"[+] Stabilita chiave AES con {address[0]}:{address[1]}")

                # Invia conferma
                welcome_msg = f"Connessione sicura stabilita con il server!"
                encrypted_welcome = CryptoUtils.encrypt_with_aes(welcome_msg.encode(), aes_key)
                client_socket.sendall(encrypted_welcome)
            else:
                # Modalità non sicura
                welcome_msg = "Connessione (NON SICURA) stabilita con il server!"
                client_socket.sendall(welcome_msg.encode())

            # Loop di ricezione messaggi
            while self.running:
                try:
                    if self.use_encryption:
                        # Ricevi dati criptati
                        encrypted_data = client_socket.recv(4096)
                        if not encrypted_data:
                            break

                        # Decripta i dati
                        data = CryptoUtils.decrypt_with_aes(encrypted_data, client_info["aes_key"])
                        message = data.decode()
                    else:
                        # Ricevi dati in chiaro
                        data = client_socket.recv(4096)
                        if not data:
                            break
                        message = data.decode()

                    if message.lower() == "quit":
                        break

                    # Stampa il messaggio ricevuto
                    print(f"[CLIENT {address[0]}:{address[1]}] {message}")

                    # Prepara la risposta
                    response = f"SERVER: Ho ricevuto il tuo messaggio: {message}"

                    # Invia la risposta
                    if self.use_encryption:
                        encrypted_response = CryptoUtils.encrypt_with_aes(response.encode(), client_info["aes_key"])
                        client_socket.sendall(encrypted_response)
                    else:
                        client_socket.sendall(response.encode())

                except Exception as e:
                    print(f"[!] Errore nella comunicazione con {address[0]}:{address[1]}: {str(e)}")
                    break

        except Exception as e:
            print(f"[!] Errore nel gestire il client {address[0]}:{address[1]}: {str(e)}")

        finally:
            # Chiudi la connessione
            try:
                client_socket.close()
                if address in self.clients:
                    del self.clients[address]
                print(f"[*] Connessione chiusa con {address[0]}:{address[1]}")
            except:
                pass

    def stop(self):
        self.running = False

        # Chiudi le connessioni client
        for address, client_info in self.clients.items():
            try:
                client_info["socket"].close()
            except:
                pass

        # Chiudi il socket del server
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        print(f"[+] Server arrestato.")


# Classe per il client TCP
class SecureTCPClient:
    def __init__(self, server_host, server_port, use_encryption=True):
        self.server_host = server_host
        self.server_port = server_port
        self.use_encryption = use_encryption
        self.client_socket = None
        self.connected = False

        # Variabili per la crittografia
        self.server_public_key = None
        self.aes_key = None

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_host, self.server_port))
            self.connected = True

            print(f"[+] Connesso al server {self.server_host}:{self.server_port}")

            if self.use_encryption:
                # 1. Ricevi la chiave pubblica del server
                server_public_key_pem = self.client_socket.recv(4096)
                self.server_public_key = CryptoUtils.deserialize_public_key(server_public_key_pem)
                print(f"[*] Ricevuta chiave pubblica dal server")

                # 2. Genera una chiave AES casuale
                self.aes_key = CryptoUtils.generate_aes_key()

                # 3. Cripta la chiave AES con la chiave pubblica del server e inviala
                encrypted_aes_key = CryptoUtils.encrypt_with_public_key(self.aes_key, self.server_public_key)
                self.client_socket.sendall(encrypted_aes_key)
                print(f"[+] Chiave AES inviata al server")

                # 4. Ricevi conferma
                encrypted_welcome = self.client_socket.recv(4096)
                welcome_msg = CryptoUtils.decrypt_with_aes(encrypted_welcome, self.aes_key).decode()
                print(f"[SERVER] {welcome_msg}")
            else:
                # Modalità non sicura
                welcome_msg = self.client_socket.recv(4096).decode()
                print(f"[SERVER] {welcome_msg}")

            return True

        except Exception as e:
            print(f"[!] Errore nella connessione: {str(e)}")
            return False

    def send_message(self, message):
        if not self.connected or not self.client_socket:
            print(f"[!] Non connesso al server.")
            return False

        try:
            if self.use_encryption:
                # Cripta il messaggio con la chiave AES
                encrypted_message = CryptoUtils.encrypt_with_aes(message.encode(), self.aes_key)
                self.client_socket.sendall(encrypted_message)
            else:
                # Invia il messaggio in chiaro
                self.client_socket.sendall(message.encode())

            return True

        except Exception as e:
            print(f"[!] Errore nell'invio del messaggio: {str(e)}")
            return False

    def receive_message(self):
        if not self.connected or not self.client_socket:
            print(f"[!] Non connesso al server.")
            return None

        try:
            if self.use_encryption:
                # Ricevi dati criptati
                encrypted_data = self.client_socket.recv(4096)
                if not encrypted_data:
                    return None

                # Decripta i dati
                data = CryptoUtils.decrypt_with_aes(encrypted_data, self.aes_key)
                return data.decode()
            else:
                # Ricevi dati in chiaro
                data = self.client_socket.recv(4096)
                if not data:
                    return None
                return data.decode()

        except Exception as e:
            print(f"[!] Errore nella ricezione del messaggio: {str(e)}")
            return None

    def close(self):
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass

        self.connected = False
        print(f"[+] Connessione chiusa.")


# Funzione principale
def main():
    parser = argparse.ArgumentParser(description="Client/Server TCP con opzione di crittografia")
    parser.add_argument("mode", choices=["server", "client"], help="Modalità di esecuzione: server o client")
    parser.add_argument("--host", default="127.0.0.1", help="Indirizzo host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Porta (default: 8000)")
    parser.add_argument("--no-encryption", action="store_true", help="Disabilita la crittografia")
    args = parser.parse_args()

    if args.mode == "server":
        server = SecureTCPServer(args.host, args.port, not args.no_encryption)

        try:
            server.start()
            # Mantiene il server in esecuzione fino a quando l'utente preme Ctrl+C
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nArrestando il server...")
        finally:
            server.stop()
    else:
        client = SecureTCPClient(args.host, args.port, not args.no_encryption)

        if not client.connect():
            return

        try:
            # Ciclo di invio/ricezione messaggi
            while True:
                message = input("Messaggio: ")

                if message.lower() == "quit":
                    client.send_message(message)
                    break

                if client.send_message(message):
                    response = client.receive_message()
                    if response:
                        print(f"[SERVER] {response}")
                    else:
                        print(f"[!] Nessuna risposta dal server o connessione persa.")
                        break

        except KeyboardInterrupt:
            print("\nChiusura della connessione...")
        finally:
            client.close()


if __name__ == "__main__":
    main()