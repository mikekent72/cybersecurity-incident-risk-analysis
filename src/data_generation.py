from datetime import datetime, timedelta
from pathlib import Path
import random

import pandas as pd


RANDOM_SEED = 42

OUTPUT_DIRECTORY = Path("data/raw")
EVENTS_FILE = OUTPUT_DIRECTORY / "security_events.csv"
USERS_FILE = OUTPUT_DIRECTORY / "users.csv"


USERS = [
    {
        "username": "jsmith",
        "department": "Finance",
        "privileged": False,
        "usual_country": "UK",
        "usual_start_hour": 8,
        "usual_end_hour": 18,
    },
    {
        "username": "agarcia",
        "department": "HR",
        "privileged": False,
        "usual_country": "UK",
        "usual_start_hour": 8,
        "usual_end_hour": 18,
    },
    {
        "username": "admin01",
        "department": "IT",
        "privileged": True,
        "usual_country": "UK",
        "usual_start_hour": 8,
        "usual_end_hour": 18,
    },
    {
        "username": "mthomas",
        "department": "Sales",
        "privileged": False,
        "usual_country": "UK",
        "usual_start_hour": 8,
        "usual_end_hour": 18,
    },
    {
        "username": "lwilson",
        "department": "Operations",
        "privileged": False,
        "usual_country": "UK",
        "usual_start_hour": 7,
        "usual_end_hour": 17,
    },
]


NORMAL_SOURCE_IPS = [
    "10.0.1.10",
    "10.0.1.11",
    "10.0.1.12",
    "10.0.1.13",
    "10.0.1.14",
]

NORMAL_DESTINATION_IPS = [
    "10.0.2.10",
    "10.0.2.11",
    "10.0.2.12",
    "10.0.2.13",
]

EXTERNAL_IPS = [
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
    "203.0.113.42",
    "198.51.100.20",
    "198.51.100.21",
]


def create_event(
    timestamp,
    event_type,
    username=None,
    source_ip=None,
    destination_ip=None,
    destination_port=None,
    protocol=None,
    action=None,
    success=None,
    country=None,
):
    """Create a single security event."""
    return {
        "event_id": None,
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "action": action,
        "success": success,
        "country": country,
    }


def generate_normal_authentication_events(start_time, count):
    """Generate normal authentication activity."""
    events = []

    for _ in range(count):
        user = random.choice(USERS)

        hour = random.randint(
            user["usual_start_hour"],
            user["usual_end_hour"] - 1,
        )

        timestamp = start_time + timedelta(
            days=random.randint(0, 6),
            hours=hour - start_time.hour,
            minutes=random.randint(0, 59),
        )

        success = random.random() > 0.08

        events.append(
            create_event(
                timestamp=timestamp,
                event_type="authentication",
                username=user["username"],
                source_ip=random.choice(NORMAL_SOURCE_IPS),
                action="login",
                success=success,
                country=user["usual_country"],
            )
        )

    return events


def generate_normal_network_events(start_time, count):
    """Generate normal network connection activity."""
    events = []

    common_ports = [22, 53, 80, 443]

    for _ in range(count):
        timestamp = start_time + timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        events.append(
            create_event(
                timestamp=timestamp,
                event_type="network",
                source_ip=random.choice(NORMAL_SOURCE_IPS),
                destination_ip=random.choice(NORMAL_DESTINATION_IPS),
                destination_port=random.choice(common_ports),
                protocol="TCP",
                action="connection",
                success=True,
            )
        )

    return events


def generate_brute_force_scenario(start_time):
    """Generate a brute-force attack followed by a successful login."""
    events = []

    attack_start = start_time + timedelta(days=2, hours=9)

    attacker_ip = "203.0.113.42"
    username = "jsmith"

    for attempt in range(14):
        events.append(
            create_event(
                timestamp=attack_start + timedelta(seconds=20 * attempt),
                event_type="authentication",
                username=username,
                source_ip=attacker_ip,
                action="login",
                success=False,
                country="UK",
            )
        )

    events.append(
        create_event(
            timestamp=attack_start + timedelta(minutes=5),
            event_type="authentication",
            username=username,
            source_ip=attacker_ip,
            action="login",
            success=True,
            country="UK",
        )
    )

    return events


def generate_port_scan_scenario(start_time):
    """Generate a concentrated network port scan."""
    events = []

    scan_start = start_time + timedelta(days=3, hours=11)
    source_ip = "198.51.100.20"
    destination_ip = "10.0.2.10"

    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        3389,
    ]

    for index, port in enumerate(ports):
        events.append(
            create_event(
                timestamp=scan_start + timedelta(seconds=index * 3),
                event_type="network",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=port,
                protocol="TCP",
                action="connection",
                success=False,
            )
        )

    return events


def generate_suspicious_account_scenario(start_time):
    """Generate unusual account activity."""
    events = []

    suspicious_time = start_time + timedelta(days=4, hours=3, minutes=17)

    events.append(
        create_event(
            timestamp=suspicious_time,
            event_type="authentication",
            username="admin01",
            source_ip="203.0.113.10",
            action="login",
            success=True,
            country="Germany",
        )
    )

    return events


def generate_borderline_events(start_time):
    """Generate activity that should not trigger detection rules."""
    events = []

    timestamp = start_time + timedelta(days=5, hours=10)

    for attempt in range(3):
        events.append(
            create_event(
                timestamp=timestamp + timedelta(minutes=attempt),
                event_type="authentication",
                username="mthomas",
                source_ip="203.0.113.11",
                action="login",
                success=False,
                country="UK",
            )
        )

    return events


def assign_event_ids(events):
    """Assign stable IDs after all events have been generated."""
    for index, event in enumerate(events, start=1):
        event["event_id"] = f"EVT-{index:04d}"

    return events


def main():
    """Generate the complete simulated security dataset."""
    random.seed(RANDOM_SEED)

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    start_time = datetime(2026, 8, 17, 8, 0, 0)

    events = []

    events.extend(
        generate_normal_authentication_events(
            start_time,
            count=350,
        )
    )

    events.extend(
        generate_normal_network_events(
            start_time,
            count=350,
        )
    )

    events.extend(generate_brute_force_scenario(start_time))
    events.extend(generate_port_scan_scenario(start_time))
    events.extend(generate_suspicious_account_scenario(start_time))
    events.extend(generate_borderline_events(start_time))

    events = assign_event_ids(events)

    events_dataframe = pd.DataFrame(events)
    events_dataframe["timestamp"] = pd.to_datetime(
        events_dataframe["timestamp"]
    )

    events_dataframe = events_dataframe.sort_values("timestamp")

    events_dataframe.to_csv(
        EVENTS_FILE,
        index=False,
    )

    users_dataframe = pd.DataFrame(USERS)

    users_dataframe.to_csv(
        USERS_FILE,
        index=False,
    )

    print(f"Generated {len(events_dataframe)} security events.")
    print(f"Saved events to: {EVENTS_FILE}")
    print(f"Saved users to: {USERS_FILE}")


if __name__ == "__main__":
    main()