from scapy.all import *

data = 'Eavesdrop_Data.pcap'
scapy_read_pcap = rdpcap(data)

sessions = scapy_read_pcap.sessions()

for session in sessions:
    for packet in sessions[session]:
        if 'UDP' in session:
            try:
                print('[*] UDP \n' + bytes(packet[UDP].payload).decode('utf-8'))
            except:
                pass
        try:
            if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                print('[*] TCP \n' + bytes(packet[TCP].payload).decode('utf-8'))
        except:
            pass

