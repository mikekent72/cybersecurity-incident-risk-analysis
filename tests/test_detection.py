import pandas as pd

from src.detection import (
    detect_brute_force,
    detect_port_scanning,
    detect_suspicious_account_activity,
)


def test_brute_force_is_detected():
    events = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp("2026-08-20 09:00:00"),
                "event_type": "authentication",
                "username": "jsmith",
                "source_ip": "203.0.113.42",
                "destination_ip": None,
                "destination_port": None,
                "protocol": None,
                "action": "login",
                "success": False,
                "country": "UK",
            }
            for _ in range(5)
        ]
    )

    for index in range(len(events)):
        events.loc[index, "timestamp"] += pd.Timedelta(
            seconds=index * 30
        )

    incidents = detect_brute_force(events)

    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == (
        "Brute-force authentication"
    )


def test_insufficient_failed_logins_are_not_detected():
    events = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp("2026-08-20 09:00:00"),
                "event_type": "authentication",
                "username": "jsmith",
                "source_ip": "203.0.113.42",
                "destination_ip": None,
                "destination_port": None,
                "protocol": None,
                "action": "login",
                "success": False,
                "country": "UK",
            }
            for _ in range(3)
        ]
    )

    incidents = detect_brute_force(events)

    assert len(incidents) == 0


def test_port_scan_is_detected():
    events = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp("2026-08-20 10:00:00")
                + pd.Timedelta(seconds=index),
                "event_type": "network",
                "username": None,
                "source_ip": "198.51.100.20",
                "destination_ip": "10.0.2.10",
                "destination_port": port,
                "protocol": "TCP",
                "action": "connection",
                "success": False,
                "country": None,
            }
            for index, port in enumerate(
                [21, 22, 23, 25, 53, 80, 110, 443]
            )
        ]
    )

    incidents = detect_port_scanning(events)

    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == (
        "Network port scanning"
    )


def test_suspicious_account_activity_is_detected():
    events = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp("2026-08-20 03:17:00"),
                "event_type": "authentication",
                "username": "admin01",
                "source_ip": "203.0.113.10",
                "destination_ip": None,
                "destination_port": None,
                "protocol": None,
                "action": "login",
                "success": True,
                "country": "Germany",
            }
        ]
    )

    users = pd.DataFrame(
        [
            {
                "username": "admin01",
                "department": "IT",
                "privileged": True,
                "usual_country": "UK",
                "usual_start_hour": 8,
                "usual_end_hour": 18,
            }
        ]
    )

    incidents = detect_suspicious_account_activity(
        events,
        users,
    )

    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == (
        "Suspicious account activity"
    )
    assert incidents[0]["severity"] == "High"