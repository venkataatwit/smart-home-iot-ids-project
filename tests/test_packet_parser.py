from scapy.all import IP, TCP

from src.detector import IntrusionDetector
from tests.sample_packets import make_syn


def test_detector_accepts_valid_ip_tcp_packet():
    detector = IntrusionDetector()
    packet = make_syn(
        src="192.168.1.10",
        dst="192.168.1.1",
        port=80,
    )

    alerts = detector.process_packet(packet)

    assert packet.haslayer(IP)
    assert packet.haslayer(TCP)
    assert isinstance(alerts, list)


def test_detector_ignores_packet_without_ip():
    detector = IntrusionDetector()
    packet = TCP(dport=80, flags="S")

    alerts = detector.process_packet(packet)

    assert alerts == []