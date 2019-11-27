#!/usr/bin/python

import socket
import threading

number_of_connections = 1
TCP = socket.SOCK_STREAM
ipv4 = socket.AF_INET

server_socket = socket.socket(ipv4, TCP)

server_socket.bind(('localhost', 1234))
server_socket.listen(number_of_connections)
print("[+] Listening...")


def handle_client(client_socket):
    request = client_socket.recv(1024).decode()
    print("[+] Received: " + str(request))
    client_socket.send("ACK".encode())
    client_socket.close()


while True:
    client, address = server_socket.accept()
    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()
