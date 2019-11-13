import paramiko


def ssh_cmd(ip, user, pwd, command):
    port = 22
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.load_system_host_keys()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        ssh_client.connect(ip, username=user, password=pwd)
        ssh_session = ssh_client.get_transport().open_session()
        if ssh_session.active:
            ssh_session.exec_command(command)
            response = ssh_session.recv(1024).decode()
            print(str(response))

    finally:
        ssh_client.close()

if __name__ == '__main__':
    user = "user"
    ip = "localhost"
    pwd = "passord123"
    command = "ClientConnected"
    ssh_cmd(ip, user, pwd, command)
