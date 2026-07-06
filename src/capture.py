from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_capture():
    sniff(prn=packet_callback, store=False)
