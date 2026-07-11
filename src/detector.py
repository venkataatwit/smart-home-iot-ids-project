from collections import defaultdict, deque
from dataclasses import dataclass
from time import time

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


@dataclass
class Alert:
    timestamp: float
    alert_type: str
    source_ip: str
    destination_ip: str
    severity: str
    description: str


class IntrusionDetector:
    def __init__(
        self,
        port_scan_threshold: int = 10,
        syn_flood_threshold: int = 50,
        traffic_spike_threshold: int = 200,
        window_seconds: int = 10,
    ) -> None:
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.traffic_spike_threshold = traffic_spike_threshold
        self.window_seconds = window_seconds

        self.port_activity: dict[tuple[str, str], deque] = defaultdict(deque)
        self.syn_activity: dict[tuple[str, str], deque] = defaultdict(deque)
        self.packet_activity: dict[str, deque] = defaultdict(deque)

        self.triggered_port_scans: set[tuple[str, str]] = set()
        self.triggered_syn_floods: set[tuple[str, str]] = set()
        self.triggered_traffic_spikes: set[str] = set()

    def process_packet(self, packet: Packet) -> list[Alert]:
        alerts: list[Alert] = []

        if not packet.haslayer(IP):
            return alerts

        current_time = float(getattr(packet, "time", time()))

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        alerts.extend(
            self._detect_traffic_spike(
                source_ip=source_ip,
                destination_ip=destination_ip,
                timestamp=current_time,
            )
        )

        if packet.haslayer(TCP):
            alerts.extend(
                self._detect_tcp_threats(
                    packet=packet,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    timestamp=current_time,
                )
            )

        return alerts

    def _detect_tcp_threats(
        self,
        packet: Packet,
        source_ip: str,
        destination_ip: str,
        timestamp: float,
    ) -> list[Alert]:
        alerts: list[Alert] = []

        tcp_layer = packet[TCP]
        flags = int(tcp_layer.flags)

        syn_set = bool(flags & 0x02)
        ack_set = bool(flags & 0x10)

        if syn_set and not ack_set:
            alerts.extend(
                self._detect_port_scan(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=int(tcp_layer.dport),
                    timestamp=timestamp,
                )
            )

            alerts.extend(
                self._detect_syn_flood(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    timestamp=timestamp,
                )
            )

        return alerts

    def _detect_port_scan(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        timestamp: float,
    ) -> list[Alert]:
        key = (source_ip, destination_ip)
        activity = self.port_activity[key]

        activity.append((timestamp, destination_port))
        self._remove_old_records(activity, timestamp)

        unique_ports = {port for _, port in activity}

        if len(unique_ports) >= self.port_scan_threshold:
            if key not in self.triggered_port_scans:
                self.triggered_port_scans.add(key)

                return [
                    Alert(
                        timestamp=timestamp,
                        alert_type="Port Scan",
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        severity="HIGH",
                        description=(
                            f"Source contacted {len(unique_ports)} unique TCP "
                            f"ports within {self.window_seconds} seconds."
                        ),
                    )
                ]
        else:
            self.triggered_port_scans.discard(key)

        return []

    def _detect_syn_flood(
        self,
        source_ip: str,
        destination_ip: str,
        timestamp: float,
    ) -> list[Alert]:
        key = (source_ip, destination_ip)
        activity = self.syn_activity[key]

        activity.append(timestamp)
        self._remove_old_records(activity, timestamp)

        if len(activity) >= self.syn_flood_threshold:
            if key not in self.triggered_syn_floods:
                self.triggered_syn_floods.add(key)

                return [
                    Alert(
                        timestamp=timestamp,
                        alert_type="SYN Flood",
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        severity="CRITICAL",
                        description=(
                            f"Detected {len(activity)} TCP SYN packets within "
                            f"{self.window_seconds} seconds."
                        ),
                    )
                ]
        else:
            self.triggered_syn_floods.discard(key)

        return []

    def _detect_traffic_spike(
        self,
        source_ip: str,
        destination_ip: str,
        timestamp: float,
    ) -> list[Alert]:
        activity = self.packet_activity[source_ip]

        activity.append(timestamp)
        self._remove_old_records(activity, timestamp)

        if len(activity) >= self.traffic_spike_threshold:
            if source_ip not in self.triggered_traffic_spikes:
                self.triggered_traffic_spikes.add(source_ip)

                return [
                    Alert(
                        timestamp=timestamp,
                        alert_type="Traffic Spike",
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        severity="MEDIUM",
                        description=(
                            f"Detected {len(activity)} packets from this source "
                            f"within {self.window_seconds} seconds."
                        ),
                    )
                ]
        else:
            self.triggered_traffic_spikes.discard(source_ip)

        return []

    def _remove_old_records(self, records: deque, timestamp: float) -> None:
        cutoff = timestamp - self.window_seconds

        while records:
            record_timestamp = (
                records[0][0]
                if isinstance(records[0], tuple)
                else records[0]
            )

            if record_timestamp >= cutoff:
                break

            records.popleft()