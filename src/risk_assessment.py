from pathlib import Path

import pandas as pd


INCIDENTS_FILE = Path("output/investigated_incidents.csv")
OUTPUT_FILE = Path("output/risk_assessed_incidents.csv")


RISK_LEVELS = {
    1: "Low",
    2: "Low",
    3: "Low",
    4: "Low",
    5: "Medium",
    6: "Medium",
    7: "Medium",
    8: "Medium",
    9: "Medium",
    10: "High",
    11: "High",
    12: "High",
    13: "High",
    14: "High",
    15: "Critical",
    16: "Critical",
    17: "Critical",
    18: "Critical",
    19: "Critical",
    20: "Critical",
    21: "Critical",
    22: "Critical",
    23: "Critical",
    24: "Critical",
    25: "Critical",
}


RISK_ASSESSMENTS = {
    "Brute-force authentication": {
        "likelihood": 4,
        "impact": 4,
        "rationale": (
            "Repeated failed authentication attempts were followed "
            "by a successful login creating credible evidence of "
            "possible account compromise."
        ),
        "mitigations": (
            "Enable multi-factor authentication (MFA), implement "
            "rate limiting or account lockout controls, monitor "
            "repeated authentication failures and review the "
            "affected account for unauthorised activity."
        ),
    },
    "Network port scanning": {
        "likelihood": 3,
        "impact": 2,
        "rationale": (
            "The activity is consistent with network reconnaissance "
            "but the available evidence does not show successful "
            "connections to the targeted services."
        ),
        "mitigations": (
            "Restrict unnecessary exposed services, apply firewall "
            "rules to limit network access, monitor repeated "
            "scanning activity and investigate whether the source "
            "was authorised."
        ),
    },
    "Suspicious account activity": {
        "likelihood": 4,
        "impact": 5,
        "rationale": (
            "A successful login to a privileged account occurred "
            "outside normal working hours and/or from an unexpected "
            "country providing credible evidence of possible "
            "credential compromise."
        ),
        "mitigations": (
            "Require MFA for privileged accounts, verify the login "
            "with the account owner, review activity performed "
            "after authentication, restrict privileged access "
            "and monitor privileged account activity."
        ),
    },
}


def load_incidents():
    """Load investigated incidents."""
    return pd.read_csv(
        INCIDENTS_FILE,
        parse_dates=["timestamp"],
    )


def assess_incident(incident):
    """Assign likelihood, impact and mitigations to an incident."""
    incident_type = incident["incident_type"]

    if incident_type not in RISK_ASSESSMENTS:
        raise ValueError(
            f"Unsupported incident type: {incident_type}"
        )

    assessment = RISK_ASSESSMENTS[incident_type]

    likelihood = assessment["likelihood"]
    impact = assessment["impact"]

    risk_score = likelihood * impact
    risk_level = RISK_LEVELS[risk_score]

    return {
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_rationale": assessment["rationale"],
        "recommended_mitigations": assessment["mitigations"],
    }


def main():
    """Assess the cybersecurity risk of all investigated incidents."""
    incidents = load_incidents()

    risk_assessments = []

    for _, incident in incidents.iterrows():
        assessment = assess_incident(incident)

        risk_assessments.append(
            {
                **incident.to_dict(),
                **assessment,
            }
        )

    risk_assessed_incidents = pd.DataFrame(
        risk_assessments
    )

    risk_assessed_incidents = risk_assessed_incidents.sort_values(
        "risk_score",
        ascending=False,
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    risk_assessed_incidents.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print(
        f"Risk assessed {len(risk_assessed_incidents)} incidents."
    )

    print(
        f"Saved risk assessment to: {OUTPUT_FILE}"
    )

    print("\nRisk summary:")

    print(
        risk_assessed_incidents[
            [
                "incident_id",
                "incident_type",
                "likelihood",
                "impact",
                "risk_score",
                "risk_level",
            ]
        ].to_string(index=False)
    )


if __name__ == "__main__":
    main()