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
* start to listen: server.listen(n) n means that we have maximum n connections. 
* Make a client handler function that can receive and respond to the client. The function should take 
a client socket as param. 
* Wait for incoming connections. When a client connects, we receive the client socket. Create
a threading object that points to the client handler function. Pass the client socket with it. 

#### Replacing netcat
[netcat](https://en.wikipedia.org/wiki/Netcat) - used to read or write from network connections using
either UDP or TCP. 
