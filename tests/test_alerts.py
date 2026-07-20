import csv

from src.alerts import initialize_alert_file, save_alert
from src.detector import Alert


def test_initialize_alert_file_creates_header(tmp_path) -> None:
    output_path = tmp_path / "alerts.csv"

    initialize_alert_file(str(output_path))

    with output_path.open("r", encoding="utf-8") as file:
        rows = list(csv.reader(file))

    assert rows[0] == [
        "timestamp",
        "alert_type",
        "source_ip",
        "destination_ip",
        "severity",
        "description",
    ]


def test_save_alert_writes_alert(tmp_path) -> None:
    output_path = tmp_path / "alerts.csv"

    alert = Alert(
        timestamp=1_700_000_000.0,
        alert_type="Port Scan",
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        severity="HIGH",
        description="Test port scan alert.",
    )

    initialize_alert_file(str(output_path))
    save_alert(alert, str(output_path))

    with output_path.open("r", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 1
    assert rows[0]["alert_type"] == "Port Scan"
    assert rows[0]["source_ip"] == "192.168.1.20"
    assert rows[0]["destination_ip"] == "192.168.1.10"
    assert rows[0]["severity"] == "HIGH"


def test_initialize_does_not_erase_existing_alerts(tmp_path) -> None:
    output_path = tmp_path / "alerts.csv"

    alert = Alert(
        timestamp=1_700_000_000.0,
        alert_type="Traffic Spike",
        source_ip="192.168.1.30",
        destination_ip="192.168.1.1",
        severity="MEDIUM",
        description="Test traffic spike.",
    )

    initialize_alert_file(str(output_path))
    save_alert(alert, str(output_path))
    initialize_alert_file(str(output_path))

    with output_path.open("r", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 1
