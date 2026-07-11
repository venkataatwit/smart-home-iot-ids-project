from src.detector import IntrusionDetector
from tests.sample_packets import make_syn


def test_port_scan_is_detected():
    detector = IntrusionDetector(
        port_scan_threshold=5,
        window_seconds=10,
    )

    alerts = []

    for index, port in enumerate([21, 22, 23, 80, 443]):
        packet = make_syn(
            src="192.168.1.50",
            dst="192.168.1.1",
            port=port,
            timestamp=float(index),
        )

        alerts.extend(detector.process_packet(packet))

    assert any(
        alert.alert_type == "Port Scan"
        for alert in alerts
    )