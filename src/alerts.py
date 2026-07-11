import csv
from datetime import datetime
from pathlib import Path

from src.detector import Alert


CSV_FIELDS = [
    "timestamp",
    "alert_type",
    "source_ip",
    "destination_ip",
    "severity",
    "description",
]


def initialize_alert_file(
    output_path: str = "data/alerts.csv",
) -> None:
    """
    Create a fresh alerts CSV file with a header.

    This overwrites the previous alerts file each time the IDS starts.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()


def save_alert(
    alert: Alert,
    output_path: str = "data/alerts.csv",
) -> None:
    """
    Append one alert to the CSV file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    file_needs_header = not path.exists() or path.stat().st_size == 0

    with path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)

        if file_needs_header:
            writer.writeheader()

        writer.writerow(
            {
                "timestamp": datetime.fromtimestamp(
                    alert.timestamp
                ).isoformat(timespec="seconds"),
                "alert_type": alert.alert_type,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "severity": alert.severity,
                "description": alert.description,
            }
        )


def save_alerts(
    alerts: list[Alert],
    output_path: str = "data/alerts.csv",
) -> None:
    """
    Append multiple alerts to the CSV file.
    """
    for alert in alerts:
        save_alert(alert, output_path)