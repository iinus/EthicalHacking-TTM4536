import socket
import threading

# create socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # SOCK_STREAM = TCP

# Bind socket to port
server.bind(('localhost', 1234))
server.listen(1)  # 1 connection
print("[+] Listening...")


def handle_client(client_socket):
    request = client_socket.recv(1024).decode()
    print("[+] Received: " + str(request))
    client_socket.send("ACK".encode())
    client_socket.close()


while True:
    client, address = server.accept()
    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()
