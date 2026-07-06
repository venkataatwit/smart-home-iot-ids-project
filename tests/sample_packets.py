from scapy.all import IP, TCP

def make_syn(src, dst, port):
    return IP(src=src, dst=dst) / TCP(dport=port, flags="S")
