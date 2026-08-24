from pathlib import Path

import pandas as pd


EVENTS_FILE = Path("data/raw/security_events.csv")
INCIDENTS_FILE = Path("output/detected_incidents.csv")
OUTPUT_FILE = Path("output/investigated_incidents.csv")


def load_data():
    """Load the security events and detected incidents."""
    events = pd.read_csv(
        EVENTS_FILE,
        parse_dates=["timestamp"],
    )

    incidents = pd.read_csv(
        INCIDENTS_FILE,
        parse_dates=["timestamp"],
    )

    return events, incidents


def investigate_brute_force(events, incident):
    """Investigate a detected brute-force incident."""
    username = incident["username"]
    source_ip = incident["source_ip"]
    timestamp = incident["timestamp"]

    window_start = timestamp
    window_end = timestamp + pd.Timedelta(minutes=5)

    related_events = events[
        (events["event_type"] == "authentication")
        & (events["username"] == username)
        & (events["source_ip"] == source_ip)
        & (events["timestamp"] >= window_start)
        & (events["timestamp"] <= window_end)
    ].sort_values("timestamp")

    failed_attempts = related_events[
        related_events["success"] == False
    ]

    successful_attempts = related_events[
        related_events["success"] == True
    ]

    failed_count = len(failed_attempts)
    successful_count = len(successful_attempts)

    if successful_count > 0:
        finding = (
            f"{failed_count} failed authentication attempts were "
            f"followed by a successful login for {username} from "
            f"{source_ip}."
        )

        implication = (
            "The successful authentication following repeated "
            "failures provides evidence of a possible account "
            "compromise and requires further investigation."
        )
    else:
        finding = (
            f"{failed_count} failed authentication attempts were "
            f"observed against {username} from {source_ip}, "
            "with no successful authentication observed in the "
            "investigated window."
        )

        implication = (
            "The activity is consistent with a brute-force attempt, "
            "but there is no evidence in the available logs that "
            "the attacker successfully authenticated."
        )

    investigation_steps = (
        "Review subsequent authentication activity, check whether "
        "the source IP is associated with other accounts, review "
        "the affected account for unusual activity and verify "
        "whether MFA was enabled."
    )

    return {
        "investigation_finding": finding,
        "security_implication": implication,
        "recommended_investigation": investigation_steps,
    }


def investigate_port_scan(events, incident):
    """Investigate a detected network port scan."""
    source_ip = incident["source_ip"]
    timestamp = incident["timestamp"]

    window_start = timestamp
    window_end = timestamp + pd.Timedelta(seconds=60)

    related_events = events[
        (events["event_type"] == "network")
        & (events["source_ip"] == source_ip)
        & (events["timestamp"] >= window_start)
        & (events["timestamp"] <= window_end)
    ].sort_values("timestamp")

    unique_ports = sorted(
        related_events["destination_port"]
        .dropna()
        .astype(int)
        .unique()
        .tolist()
    )

    unique_hosts = (
        related_events["destination_ip"]
        .dropna()
        .nunique()
    )

    successful_connections = related_events[
        related_events["success"] == True
    ]

    finding = (
        f"Source {source_ip} attempted connections to "
        f"{len(unique_ports)} distinct ports across "
        f"{unique_hosts} destination host(s)."
    )

    implication = (
        "The concentrated probing activity is consistent with "
        "network reconnaissance. An attacker could use this "
        "information to identify exposed services for subsequent "
        "targeting."
    )

    if len(successful_connections) > 0:
        implication += (
            " At least one connection attempt was successful, "
            "increasing the need to investigate the exposed "
            "services."
        )

    investigation_steps = (
        "Identify the system associated with the source IP, "
        "determine whether the scanning was authorised, review "
        "the targeted hosts and services and investigate any "
        "subsequent connections from the same source."
    )

    return {
        "investigation_finding": finding,
        "security_implication": implication,
        "recommended_investigation": investigation_steps,
    }


def investigate_suspicious_account(events, incident):
    """Investigate suspicious account activity."""
    username = incident["username"]
    source_ip = incident["source_ip"]
    timestamp = incident["timestamp"]

    window_start = timestamp - pd.Timedelta(hours=1)
    window_end = timestamp + pd.Timedelta(hours=1)

    related_events = events[
        (events["event_type"] == "authentication")
        & (events["username"] == username)
        & (events["timestamp"] >= window_start)
        & (events["timestamp"] <= window_end)
    ].sort_values("timestamp")

    failed_attempts = related_events[
        related_events["success"] == False
    ]

    successful_attempts = related_events[
        related_events["success"] == True
    ]

    countries = (
        successful_attempts["country"]
        .dropna()
        .unique()
        .tolist()
    )

    finding = (
        f"A successful authentication for {username} was observed "
        f"from {source_ip} at {timestamp.strftime('%H:%M')}. "
        f"The login originated from {countries[0]}, "
        f"rather than the user's usual country of the UK."
    )

    implication = (
        "The authentication differs from the user's established "
        "baseline and may indicate compromised credentials or "
        "legitimate activity that requires verification."
    )

    investigation_steps = (
        "Verify the user's activity with the account owner, review "
        "recent authentication history, check for password changes "
        "or MFA events, review activity performed after the login "
        "and investigate whether the source IP has been associated "
        "with other suspicious activity."
    )

    return {
        "investigation_finding": finding,
        "security_implication": implication,
        "recommended_investigation": investigation_steps,
    }


def investigate_incident(events, incident):
    """Investigate an incident according to its type."""
    incident_type = incident["incident_type"]

    if incident_type == "Brute-force authentication":
        return investigate_brute_force(
            events,
            incident,
        )

    if incident_type == "Network port scanning":
        return investigate_port_scan(
            events,
            incident,
        )

    if incident_type == "Suspicious account activity":
        return investigate_suspicious_account(
            events,
            incident,
        )

    raise ValueError(
        f"Unsupported incident type: {incident_type}"
    )


def main():
    """Investigate all detected security incidents."""
    events, incidents = load_data()

    investigation_results = []

    for _, incident in incidents.iterrows():
        result = investigate_incident(
            events,
            incident,
        )

        investigation_results.append(
            {
                **incident.to_dict(),
                **result,
            }
        )

    investigated_incidents = pd.DataFrame(
        investigation_results
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    investigated_incidents.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print(
        f"Investigated {len(investigated_incidents)} incidents."
    )
    print(
        f"Saved investigations to: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()