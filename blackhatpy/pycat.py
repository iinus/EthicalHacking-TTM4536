#!/usr/bin/python
# Compiled with python 3.
# This is a script that implements netcat functionality similar to blackhat python.
# More functionality and options could be added

from optparse import OptionParser
import sys
import socket
import threading
import subprocess

command_shell = False
execute_cmd = ""
color_cmd = '\033[95m\033[1m'
color_text = '\33[96m\033[1m'
color_end = '\033[0m'


def client_sender(user_buffer, target_host, target_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((target_host, target_port))
        if len(user_buffer) > 0:
            client_socket.send(user_buffer.encode())
        while True:
            receive_len = 1
            response = ""
            while receive_len > 0:
                response += client_socket.recv(4096).decode()
                print(str(response))
                receive_len = len(response)
                if receive_len < 4096:
                    break
            user_buffer = input("")
            user_buffer += "\n"
            client_socket.send(user_buffer.encode())
    finally:
        client_socket.close()


def server_loop(target_host, target_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((target_host, target_port))
    server_socket.listen(2)

    while True:
        client, address = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()


def handle_client(client_socket):
    global execute_cmd
    global command_shell

    if len(execute_cmd) > 0:
        output = run_command(execute_cmd)
        client_socket.send(output.encode())

    if command_shell:
        while True:
            print("sending <PyCat-shell #> ")
            message = color_cmd + " <PyCat-shell #>"
            client_socket.send(message.encode())
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024).decode()
                response = color_text + run_command(str(cmd_buffer)) + color_end
                client_socket.send(response.encode())


def run_command(command):
    output = ""
    print("[+] Trying to execute cmd: " + command)
    try:
        output = subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE)
        print("[+] Command output: " + str(output.stdout))
    except:
        print("[-] Failed to execute command :(")

    return (output.stdout).decode('utf-8')


def main():
    global command_shell
    global execute_cmd

    usage = "usage: python3 %prog [options] [arg1] [arg2]"
    parser = OptionParser(usage=usage, version="%prog 1.0")
    parser.add_option("-l", help="Listen on host:port for incoming connections", action='store_true', default=False,
                      dest="listen")
    parser.add_option("-t", help="specify a [target host]", default="localhost", dest="target")
    parser.add_option("-p", help="Specify a [port]", default=1234, dest="port")
    parser.add_option("-e", help="Execute the given [command]", default="", dest="execute")
    parser.add_option("-c", help="Initialize a command shell", action='store_true', default=False,
                      dest="command_shell")

    (options, args) = parser.parse_args()
    print(options)

    listen_ = options.listen
    command_shell = options.command_shell
    execute_cmd = options.execute
    target_host = options.target
    target_port = int(options.port)

    if not listen_ and target_port > 0:
        user_buffer = sys.stdin.read()
        client_sender(user_buffer, target_host, target_port)
    if listen_:
        server_loop(target_host, target_port)


if __name__ == '__main__':
    main()
