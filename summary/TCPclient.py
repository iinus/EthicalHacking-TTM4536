#!/usr/bin/python

import socket

ipv4 = socket.AF_INET
TCP = socket.SOCK_STREAM
server_address = ('localhost', 1234)

client_socket = socket.socket(ipv4, TCP)
client_socket.connect(server_address)

try:
    message = "halloen!"
    client_socket.send(message.encode())
    response = client_socket.recv(1234)
    print("[+] response: " + str(response))
finally:
    client_socket.close()
    print("[+] closed connection ")

