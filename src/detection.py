from pathlib import Path

import pandas as pd


EVENTS_FILE = Path("data/raw/security_events.csv")
USERS_FILE = Path("data/raw/users.csv")
OUTPUT_FILE = Path("output/detected_incidents.csv")


BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

PORT_SCAN_THRESHOLD = 8
PORT_SCAN_WINDOW_SECONDS = 60

SUSPICIOUS_LOGIN_AFTER_HOUR = 22
SUSPICIOUS_LOGIN_BEFORE_HOUR = 6


def load_data():
    """Load the simulated security events and user information."""
    events = pd.read_csv(
        EVENTS_FILE,
        parse_dates=["timestamp"],
    )

    users = pd.read_csv(USERS_FILE)

    return events, users


def create_incident(
    incident_type,
    severity,
    timestamp,
    source_ip,
    username=None,
    evidence=None,
):
    """Create a standard incident record."""
    return {
        "incident_id": None,
        "incident_type": incident_type,
        "severity": severity,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "evidence": evidence,
    }


def detect_brute_force(events):
    """
    Detect repeated failed authentication attempts from the same
    source IP against the same account within a short time window.
    """
    authentication_events = events[
        (events["event_type"] == "authentication")
        & (events["success"] == False)
    ].copy()

    authentication_events = authentication_events.sort_values("timestamp")

    incidents = []

    grouped = authentication_events.groupby(
        ["username", "source_ip"]
    )

    for (username, source_ip), group in grouped:
        group = group.sort_values("timestamp").reset_index(drop=True)

        for index in range(len(group)):
            window_start = group.loc[index, "timestamp"]
            window_end = window_start + pd.Timedelta(
                minutes=BRUTE_FORCE_WINDOW_MINUTES
            )

            window = group[
                (group["timestamp"] >= window_start)
                & (group["timestamp"] <= window_end)
            ]

            if len(window) >= BRUTE_FORCE_THRESHOLD:
                first_event = window.iloc[0]
                last_event = window.iloc[-1]

                evidence = (
                    f"{len(window)} failed login attempts against "
                    f"{username} from {source_ip} within "
                    f"{int(
                        (last_event["timestamp"] - first_event["timestamp"])
                        .total_seconds()
                        // 60
                    )} "    
                    f"minutes."
                )

                incidents.append(
                    create_incident(
                        incident_type="Brute-force authentication",
                        severity="High",
                        timestamp=first_event["timestamp"],
                        source_ip=source_ip,
                        username=username,
                        evidence=evidence,
                    )
                )

                break

    return incidents


def detect_port_scanning(events):
    """
    Detect a source IP connecting to many distinct destination ports
    within a short time window.
    """
    network_events = events[
        events["event_type"] == "network"
    ].copy()

    network_events = network_events.sort_values("timestamp")

    incidents = []

    for source_ip, group in network_events.groupby("source_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)

        for index in range(len(group)):
            window_start = group.loc[index, "timestamp"]
            window_end = window_start + pd.Timedelta(
                seconds=PORT_SCAN_WINDOW_SECONDS
            )

            window = group[
                (group["timestamp"] >= window_start)
                & (group["timestamp"] <= window_end)
            ]

            unique_ports = window["destination_port"].nunique()

            if unique_ports >= PORT_SCAN_THRESHOLD:
                first_event = window.iloc[0]

                evidence = (
                    f"Source {source_ip} contacted "
                    f"{unique_ports} distinct destination ports "
                    f"within {PORT_SCAN_WINDOW_SECONDS} seconds."
                )

                incidents.append(
                    create_incident(
                        incident_type="Network port scanning",
                        severity="Medium",
                        timestamp=first_event["timestamp"],
                        source_ip=source_ip,
                        evidence=evidence,
                    )
                )

                break

    return incidents


def detect_suspicious_account_activity(events, users):
    """
    Detect successful authentication outside a user's normal
    working hours or from an unexpected country.
    """
    authentication_events = events[
        (events["event_type"] == "authentication")
        & (events["success"] == True)
    ].copy()

    authentication_events["hour"] = (
        authentication_events["timestamp"].dt.hour
    )

    merged = authentication_events.merge(
        users,
        on="username",
        how="left",
    )

    incidents = []

    for _, event in merged.iterrows():
        unusual_time = (
            event["hour"] < event["usual_start_hour"]
            or event["hour"] >= event["usual_end_hour"]
        )

        unusual_country = (
            event["country"] != event["usual_country"]
        )

        if unusual_time or unusual_country:
            reasons = []

            if unusual_time:
                reasons.append(
                    f"login occurred at {event['hour']:02d}:"
                    f"{event['timestamp'].minute:02d}, outside "
                    f"normal working hours"
                )

            if unusual_country:
                reasons.append(
                    f"login originated from {event['country']} "
                    f"instead of usual country "
                    f"{event['usual_country']}"
                )

            evidence = (
                f"Successful login for {event['username']} from "
                f"{event['source_ip']}. "
                + "; ".join(reasons)
                + "."
            )

            severity = (
                "High"
                if event["privileged"]
                else "Medium"
            )

            incidents.append(
                create_incident(
                    incident_type="Suspicious account activity",
                    severity=severity,
                    timestamp=event["timestamp"],
                    source_ip=event["source_ip"],
                    username=event["username"],
                    evidence=evidence,
                )
            )

    return incidents


def assign_incident_ids(incidents):
    """Assign stable IDs to detected incidents."""
    for index, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-{index:03d}"

    return incidents


def main():
    """Run all detection rules and save the resulting incidents."""
    events, users = load_data()

    incidents = []

    incidents.extend(
        detect_brute_force(events)
    )

    incidents.extend(
        detect_port_scanning(events)
    )

    incidents.extend(
        detect_suspicious_account_activity(
            events,
            users,
        )
    )

    incidents = sorted(
        incidents,
        key=lambda incident: incident["timestamp"],
    )

    incidents = assign_incident_ids(incidents)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    incidents_dataframe = pd.DataFrame(incidents)

    incidents_dataframe.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print(f"Detected {len(incidents_dataframe)} incidents.")
    print(f"Saved incidents to: {OUTPUT_FILE}")

    if not incidents_dataframe.empty:
        print("\nIncident summary:")
        print(
            incidents_dataframe[
                [
                    "incident_id",
                    "incident_type",
                    "severity",
                    "username",
                    "source_ip",
                ]
            ].to_string(index=False)
        )


if __name__ == "__main__":
    main()