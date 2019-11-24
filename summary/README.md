# Summary Ethical Hacking TTM4536
This summary is written in relation to the exam in **TTM4536**. So I
extracted the stuff the professor cares about the most + a bit DuckDuckGoing. 

The book: _Black Hat Python_ was published by Justin Seitz in 2014.
The book is about writing network sniffers, manipulating packets, infecting virtual machines, creating stealthy trojans, and more. 
Unfortunately, it is written in Python 2.7 (but I wrote a couple of them in py 3 without problem). 

#### Content
1. [ Chapter 1](#chap1)
2. [ Chapter 2](#chap2)
3. [ Chapter 3](#chap3)
4. [ Chapter 4](#chap4)
5. [ Chapter 5](#chap5)
6. [ Chapter 6](#chap6)
7. [ Chapter 7](#chap7)
8. [ Web Security](#WebSec) \
    8.1 [ XSS ](#XSS) \
    8.2 [ SQL injection ](#SQL)
9. [ SpyWare ](#spyware)
10. [ MISC (other stuff we can be asked) ](#misc)

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
> After the book was published, Scapy got more functionality - some of the functions in the book are now doing stuff
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
 
#### Web_app_mapper.py
A script for hunting all files that are reachable on the remote target. 

<a name="chap6"></a>
## Chapter 6: Extending Burp Proxy

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
* LKL Linux Keylogger
* logkeys
* simple-key-logger
* PyKeylogger
* keylogger.py (in blackboard)
* Hardware Keylogger Standalone Edition 

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