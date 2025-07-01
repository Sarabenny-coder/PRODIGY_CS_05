
from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = ''
        payload = ''

        if TCP in packet:
            proto = 'TCP'
        elif UDP in packet:
            proto = 'UDP'
        else:
            proto = packet[IP].proto

        if Raw in packet:
            payload = packet[Raw].load.hex()

        print(f"[+] Src: {ip_src} --> Dst: {ip_dst} | Protocol: {proto}")
        if payload:
            print(f"    Payload: {payload}")

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
