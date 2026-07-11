class IntrusionDetector:
    def __init__(
        self,
        port_scan_threshold: int = 10,
        syn_flood_threshold: int = 50,
        traffic_spike_threshold: int = 500,
        window_seconds: int = 10,
        alert_cooldown_seconds: int = 60,
    ) -> None:
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.traffic_spike_threshold = traffic_spike_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds

        self.port_activity: dict[tuple[str, str], deque] = defaultdict(deque)
        self.syn_activity: dict[tuple[str, str], deque] = defaultdict(deque)
        self.packet_activity: dict[str, deque] = defaultdict(deque)

        self.last_port_scan_alert: dict[tuple[str, str], float] = {}
        self.last_syn_flood_alert: dict[tuple[str, str], float] = {}
        self.last_traffic_spike_alert: dict[str, float] = {}