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


def save_alert(
    alert: Alert,
    output_path: str = "data/alerts.csv",
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    file_exists = path.exists()
    file_is_empty = not file_exists or path.stat().st_size == 0

    with path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)

        if file_is_empty:
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
