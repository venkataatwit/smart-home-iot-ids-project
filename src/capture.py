from collections.abc import Callable

from scapy.packet import Packet
from scapy.all import sniff


def start_capture(
    packet_handler: Callable[[Packet], None],
    interface: str | None = None,
    packet_count: int = 0,
) -> None:
    """Capture packets and send each packet to the provided handler."""

    sniff(
        iface=interface,
        prn=packet_handler,
        store=False,
        count=packet_count,
    )