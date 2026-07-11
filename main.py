from scapy.packet import Packet

from src.alerts import save_alert
from src.capture import start_capture
from src.detector import IntrusionDetector


detector = IntrusionDetector()


def handle_packet(packet: Packet) -> None:
    alerts = detector.process_packet(packet)

    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.alert_type} | "
            f"{alert.source_ip} -> {alert.destination_ip} | "
            f"{alert.description}"
        )

        save_alert(alert)


def main() -> None:
    print("Starting Smart Home IoT Intrusion Detection System...")
    print("Monitoring live network traffic.")
    print("Press Ctrl+C to stop.\n")

    try:
        start_capture(packet_handler=handle_packet)
    except PermissionError:
        print(
            "Permission denied. Run the terminal as Administrator "
            "or use sudo on Linux."
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")


if __name__ == "__main__":
    main()