from src.detector import IntrusionDetector
from tests.sample_packets import make_syn


def test_syn_flood_is_detected():
    detector = IntrusionDetector(
        port_scan_threshold=100,
        syn_flood_threshold=5,
        window_seconds=10,
    )

    alerts = []

    for index in range(5):
        packet = make_syn(
            src="192.168.1.60",
            dst="192.168.1.1",
            port=80,
            timestamp=float(index),
        )

        alerts.extend(detector.process_packet(packet))

    assert any(
        alert.alert_type == "SYN Flood"
        for alert in alerts
    )