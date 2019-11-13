#!/usr/bin/python

import socket

server_address = ('localhost', 1234)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect(server_address)

try:
    message = "hello!"
    client.send(message.encode())
    response = client.recv(1234)
    print("[+] response: " + str(response))
finally:
    client.close()
    print("[+] closed connection ")

