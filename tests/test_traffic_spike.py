from scapy.all import IP, UDP

from src.detector import IntrusionDetector


def test_traffic_spike_is_detected():
    detector = IntrusionDetector(
        traffic_spike_threshold=5,
        window_seconds=10,
    )

    alerts = []

    for index in range(5):
        packet = (
            IP(src="192.168.1.70", dst="192.168.1.1")
            / UDP(sport=5000, dport=1883)
        )

        packet.time = float(index)
        alerts.extend(detector.process_packet(packet))

    assert any(
        alert.alert_type == "Traffic Spike"
        for alert in alerts
    )