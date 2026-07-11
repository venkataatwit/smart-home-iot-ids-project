from scapy.packet import Packet

from src.alerts import initialize_alert_file, save_alert
from src.capture import start_capture
from src.detector import IntrusionDetector


detector = IntrusionDetector(
    port_scan_threshold=10,
    syn_flood_threshold=50,
    traffic_spike_threshold=750,
    window_seconds=10,
    alert_cooldown_seconds=60,
)

packet_count = 0


def handle_packet(packet: Packet) -> None:
    global packet_count

    packet_count += 1

    # Show progress without printing every packet.
    if packet_count % 50 == 0:
        print(f"Captured {packet_count} packets...")

    alerts = detector.process_packet(packet)

    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.alert_type} | "
            f"{alert.source_ip} -> {alert.destination_ip} | "
            f"{alert.description}"
        )

        save_alert(alert)


def main() -> None:
    initialize_alert_file()

    print("Starting Smart Home IoT Intrusion Detection System...")
    print("Monitoring live network traffic.")
    print("A progress message will appear every 50 packets.")
    print("Press Ctrl+C to stop.\n")

    try:
        start_capture(packet_handler=handle_packet)

    except PermissionError:
        print(
            "\nPermission denied. Open PowerShell as Administrator "
            "and run the program again."
        )

    except KeyboardInterrupt:
        print(f"\nCapture stopped. Total packets captured: {packet_count}")


if __name__ == "__main__":
    main()
