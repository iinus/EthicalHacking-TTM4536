#!/usr/bin/python
import os
import socket
import struct
import time
import threading
import sys
from ctypes import *
from netaddr import IPNetwork, IPAddress

host_to_listen_on = ""  # E.g. use ifconfig and set this to your ip
subnet = "129.241.0.0/24"
socket_protocol = socket.IPPROTO_ICMP
windows = "nt"


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte, 4),
        ("code", c_ubyte, 4),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort),
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


def calculate_where_ICMP_starts(header_length, raw_buffer):
    offset = header_length * 4
    ICMP_buffer = raw_buffer[offset:offset + sizeof(ICMP)]
    return ICMP_buffer


def udp_sender():
    time.sleep(5)
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender_socket.sendto("PyScanner".encode(), ("%s" % ip, 65212))
        except:
            pass

if os.name == windows:
    socket_protocol = socket.IPPROTO_IP

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
raw_socket.bind((host_to_listen_on, 0))
raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == windows:
    raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


thread = threading.Thread(target=udp_sender())
thread.start()

try:
    while True:
        read_single_raw_packet = raw_socket.recvfrom(65565)[0]
        ip_header = IP(read_single_raw_packet[0:20])
        print("[IP-protocol] %s %s ---> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        if ip_header.protocol == 'ICMP':
            ICMP_buffer = calculate_where_ICMP_starts(ip_header.ihl, read_single_raw_packet)
            ICMP_header = ICMP(ICMP_buffer)
            print("[ICMP] Type: %d Code: %d" % (ICMP_header.type, ICMP_header.code))

except:
    sys.exit()
