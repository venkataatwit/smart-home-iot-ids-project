from scapy.all import IP, TCP


def make_syn(
    src: str,
    dst: str,
    port: int,
    timestamp: float = 1.0,
):
    packet = IP(src=src, dst=dst) / TCP(
        sport=40000,
        dport=port,
        flags="S",
    )

    packet.time = timestamp
    return packet