# Summary
_Black Hat Python_ was published by Justin Seitz in 2014.
The book is about writing network sniffers, manipulating packets, infecting virtual machines, creating stealthy trojans, and more. 
Unfortunately, it is written in Python 2.7 (but I wrote a couple of them in py 3 without problem). This summary is written in relation to the exam in **TTM4536**. So I
extracted the stuff the professor cares about the most + a bit DuckDuckGoing. 

1. [ Chapter 1](#chap1)
2. [ Chapter 2](#chap2)
3. [ Chapter 3](#chap3)
4. [ Chapter 4](#chap4)
5. [ MISC (other stuff we can be asked) ](#misc)

<a name="chap1"></a>
## Chapter 1 
The book walks through setting up a VM for Kali Linux (but I'm sticking to my Mac<3 for obvious reasons). Kali was designed by Offensive Security, and 
is based on Debian. It comes with a bunch of hacking-tools installed from before, e.g. Hydra (password cracking) and Metasploit (known exploits).

<a name="chap2"></a>
## Chapter 2: Network Basics
[Socket module](https://docs.python.org/3/library/socket.html)

### TCP client
Three steps:
* Create socket: client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
* Connect the client: client.connect(target_host, target_port)
* start sending and receiving 

Important parameters:
* AF_INET: we're using standard ipv4 address or a common hostname.
* SOC_STREAM: this will be a TCP client. 

### UDP client
Similar to TCP client, but:
* UDP is connectionless so we don't connect the client. 
* SOC_DGRAM: says it will be a UDP client (instead of SOC_STREAM)

### TCP server
* Create socket
* server.bind(ip, port):  _bind()_ is used to associate the socket with the server address. 
* start to listen: _server.listen(n)_ n means that we have maximum n connections. 
* Make a client handler function that can receive and respond to the client. The function should take 
a client socket as param. 
* Wait for incoming connections. When a client connects, we receive the client socket. Create
a threading object that points to the client handler function. Pass the client socket with it. 

### Replacing netcat
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

Try it out! 

![Alt text](figures/pycat.png?raw=true)

### TCP Proxy

### SSH client with paramiko
[Paramiko](https://www.paramiko.org/)
* Paramiko is a python implementation of SSHv2.
* _set_missing_host_key_policy(policy)_ - Set policy to use when connecting to servers without a known host key.
* _paramiko.AutoAddPolicy_ - Policy for automatically adding the hostname and new host key to the local HostKeys object, and saving it.
* _connect_ - connect the client to a SSH server and authenticate it. 
* _ssh_client.get_transport().open_session()_ - _get_transport()_ returns the underlying Transport object for this SSH connection.
This is can be used to open a session. 
* _ssh_session.exec_command(command)_ - execute a command on the ssh server

<a name="chap3"></a>
## Chapter 3: The network
### Building a UDP host discovery tool 
[Socket module](https://docs.python.org/3/library/socket.html)

* Why UDP? Simple and no overhead. 
* Windows requires some extra flags through a Socket Input/Output Control (IOCTL). 
This enables network [Promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode). 
* _socket.IPPROTO_IP_: Windows allow us to sniff all incoming packets
* _socket.IPPROTO_ICMP_: Linux forces us to specify ICMP. 
* _socket.SOCK_RAW_: In the sniffer, we create a raw socket 
* _raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)_: set parameters to include IP headers. 
* [netaddr](https://pypi.org/project/netaddr/) - to cover subnets. 

**Decoding IP Layer**
* Goal: decode from binary to human-readable.
* [ctypes](https://docs.python.org/3/library/ctypes.html) - we're using this module to create a C-like structure to map 
the first 20 bytes into a readable IP header. We can also use this module to create a C-like structure to decode ICMP responses.
* [struct](https://docs.python.org/3/library/struct.html) - this module performs conversions between Python values and C structs represented as Python bytes objects.

<a name="chap4"></a>
## Chapter 4: Owning the network with Scapy
** BTW ** After the book was published, Scapy got more functionality - some of the functions in the book are now doing stuff
that Scapy already can. 

[Scapy](https://scapy.readthedocs.io/en/latest/) - Scapy is a Python program that enables the user to send, 
sniff and dissect and forge network packets. This capability allows construction of tools that can probe, scan or attack networks.

Install: 
<pre> $ pip install scapy
</pre>

You can start a scapy interactive shell to try it out by typing _scapy_ in your terminal. 

To list available commands, use _lsc()_.

To list supported protocols, use _ls()_. 

To see the fields of a layer, use _ls(layer)_:

![Alt text](figures/ls.png?raw=true)

### Build a sniffer with scapy
* _sniff(filter="", iface="any", prn=function, count=N)_ 
* _filter_ is for defining a BPF filter (like in Wireshark). If it is left blank, then we sniff all packets. 
E.g.: filter="tcp port 80 or tcp port 443". 
* _iface_ is for specifying network interface. 
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
* You can extract info from other layers that Scapy support as well. An search for patterns with regular expressions (use the module _re_ in python)


<a name="misc"></a>
## MISC
** Other questions we might get ** 

### What is the difference between stored- and reflected xss?
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

### Everything you know about SQL Injection Attacks?
SQL injection is a kind of injection attack where an attacker injects SQL queries through an input field in the client app.
It is one of the most common web-hacks.

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

### When setting up a virtual machine in VirtualBox, explain in brief as many system components as you can, that should be defined for the machine.
* Operating system
* Size of base RAM memory
* CPUs
* Size of video memory
* Size of hard disk 
* Network adapter type
* Shared folders