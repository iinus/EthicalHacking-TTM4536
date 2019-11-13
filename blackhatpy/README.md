# Summary
_Black Hat Python_ was published by Justin Seitz in 2014.
The book is about writing network sniffers, manipulating packets, infecting virtual machines, creating stealthy trojans, and more. 
Unfortunately, it is written in Python 2.7. This summary is written in relation to the exam in **TTM4536**. So I
extracted the stuff the professor cares about the most + a bit DuckDuckGoing. 

## Chapter 1 
The book walks through setting up a VM for Kali Linux (but I'm sticking to my Mac<3 for obvious reasons). Kali was designed by Offensive Security, and 
is based on Debian. It comes with a bunch of hacking-tools installed from before, e.g. Hydra (password cracking) and Metasploit (known exploits).

## Chapter 2: Network Basics
[Socket module](https://docs.python.org/3/library/socket.html)

#### TCP client
Three steps:
* Create socket: client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
* Connect the client: client.connect(target_host, target_port)
* start sending and receiving 

Important parameters:
* AF_INET: we're using standard ipv4 address or a common hostname.
* SOC_STREAM: this will be a TCP client. 

#### UDP client
Similar to TCP client, but:
* UDP is connectionless so we don't connect the client. 
* SOC_DGRAM: says it will be a UDP client (instead of SOC_STREAM)

#### TCP server
* Create socket
* server.bind(ip, port):  _bind()_ is used to associate the socket with the server address. 
* start to listen: _server.listen(n)_ n means that we have maximum n connections. 
* Make a client handler function that can receive and respond to the client. The function should take 
a client socket as param. 
* Wait for incoming connections. When a client connects, we receive the client socket. Create
a threading object that points to the client handler function. Pass the client socket with it. 

#### Replacing netcat
[netcat](https://en.wikipedia.org/wiki/Netcat) - used to read or write from network connections using
either UDP or TCP. 

[subprocess](https://docs.python.org/3/library/subprocess.html) - The subprocess module allows you to spawn new processes,
 connect to their input/output/error pipes, and obtain their return codes.  

Why replace netcat? We can imagine a scenario where you hacked into a network NETX, where netcat is **not** installed.
NETX has Python installed.
From NETX you want to hack into NETY. As you can't use netcat, we can write the same functionality in Python.
Another scenario where this can be useful is in situations where you need to add some extra/special functionality
to netcat. Then, writing your own can be useful. 

[replacing netcat with python](https://www.cybrary.it/0p3n/create-netcat-replacement-python-part-1/) - article

* Specify options like target_host, target_port, command, command_shell. 
* Netcat python will have two main functionalities: listen (server) and not listen (client)
* After the server binds and the client connects, we can start with command_shell and commands.
* Use subprocess to execute commands. 

#### TCP Proxy

#### SSH client with paramiko
[Paramiko](https://www.paramiko.org/)
* Paramiko is a python implementation of SSHv2.
* _set_missing_host_key_policy(policy)_ - Set policy to use when connecting to servers without a known host key.
* _paramiko.AutoAddPolicy_ - Policy for automatically adding the hostname and new host key to the local HostKeys object, and saving it.
* _connect_ - connect the client to a SSH server and authenticate it. 
* _ssh_client.get_transport().open_session()_ - _get_transport()_ returns the underlying Transport object for this SSH connection.
This is can be used to open a session. 
* _ssh_session.exec_command(command)_ - execute a command on the ssh server

## MISC
** Other questions we might get ** 

#### What is the difference between stored- and reflected xss?
**Stored attacks** are those where the injected script is permanently stored on the target servers,
such as in a database, in a message forum, visitor log, comment field, etc. 
The victim then retrieves the malicious script from the server when it requests the stored information.
Stored XSS is also sometimes referred to as Persistent or Type-I XSS.

**Reflected attacks** are those where the injected script is reflected off the web server, such as in an error message, 
search result, or any other response that includes some or all of the input sent to the server as part of the request. 
Reflected attacks are delivered to victims via another route, such as in an e-mail message, or on some other website.
When a user is tricked into clicking on a malicious link, submitting a specially crafted form, or even just browsing to a malicious site,
the injected code travels to the vulnerable web site, which reflects the attack back to the user’s browser. 
The browser then executes the code because it came from a "trusted" server. 
Reflected XSS is also sometimes referred to as Non-Persistent or Type-II XSS.