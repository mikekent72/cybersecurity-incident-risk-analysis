from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


EVENTS_FILE = Path("data/raw/security_events.csv")
INPUT_FILE = Path("output/risk_assessed_incidents.csv")
OUTPUT_DIRECTORY = Path("output")
REPORT_FILE = OUTPUT_DIRECTORY / "security_report.html"


def load_data():
    """Load the security events and final risk assessments."""
    events = pd.read_csv(
        EVENTS_FILE,
        parse_dates=["timestamp"],
    )

    incidents = pd.read_csv(
        INPUT_FILE,
        parse_dates=["timestamp"],
    )

    return events, incidents


def calculate_summary(data, event_count):
    """Calculate high-level project statistics."""
    return {
        "events": event_count,
        "incidents": len(data),
        "critical_risk": len(
            data[data["risk_level"] == "Critical"]
        ),
        "high_risk": len(
            data[data["risk_level"] == "High"]
        ),
        "medium_risk": len(
            data[data["risk_level"] == "Medium"]
        ),
        "low_risk": len(
            data[data["risk_level"] == "Low"]
        ),
    }


def create_risk_chart(data):
    """Create a likelihood versus impact risk matrix."""
    fig, ax = plt.subplots(figsize=(7, 6))

    for _, incident in data.iterrows():
        ax.scatter(
            incident["likelihood"],
            incident["impact"],
            s=120,
        )

        ax.annotate(
            incident["incident_id"],
            (
                incident["likelihood"],
                incident["impact"],
            ),
            xytext=(7, 7),
            textcoords="offset points",
        )

    ax.set_title("Security Incident Risk Matrix")
    ax.set_xlabel("Likelihood")
    ax.set_ylabel("Impact")

    ax.set_xticks(range(1, 6))
    ax.set_yticks(range(1, 6))

    ax.set_xlim(0.5, 5.5)
    ax.set_ylim(0.5, 5.5)

    ax.grid(True, alpha=0.3)

    chart_file = OUTPUT_DIRECTORY / "risk_matrix.png"

    fig.tight_layout()
    fig.savefig(chart_file, dpi=150)
    plt.close(fig)

    return chart_file


def create_incident_chart(data):
    """Create a chart showing the risk score of each incident."""
    ordered = data.sort_values(
        "risk_score",
        ascending=True,
    )

    fig, ax = plt.subplots(figsize=(8, 5))

    ax.barh(
        ordered["incident_id"],
        ordered["risk_score"],
    )

    ax.set_title("Incident Risk Scores")
    ax.set_xlabel("Risk Score")
    ax.set_ylabel("Incident")

    ax.set_xlim(0, 25)
    ax.grid(axis="x", alpha=0.3)

    chart_file = OUTPUT_DIRECTORY / "incident_risk_scores.png"

    fig.tight_layout()
    fig.savefig(chart_file, dpi=150)
    plt.close(fig)

    return chart_file


def create_report(events, data):
    """Generate the HTML security analysis report."""
    summary = calculate_summary(
        data,
        len(events),
    )

    risk_matrix = create_risk_chart(data)
    risk_scores = create_incident_chart(data)

    incident_rows = ""

    for _, incident in data.iterrows():
        incident_rows += f"""
        <tr>
            <td>{incident['incident_id']}</td>
            <td>{incident['incident_type']}</td>
            <td>{incident['risk_score']}</td>
            <td>{incident['risk_level']}</td>
        </tr>
        """

    investigation_sections = ""

    for _, incident in data.iterrows():
        investigation_sections += f"""
        <section>
            <h3>
                {incident['incident_id']} –
                {incident['incident_type']}
            </h3>

            <p>
                <strong>Finding:</strong>
                {incident['investigation_finding']}
            </p>

            <p>
                <strong>Security implication:</strong>
                {incident['security_implication']}
            </p>

            <p>
                <strong>Risk assessment:</strong>
                Likelihood {incident['likelihood']}/5 ×
                Impact {incident['impact']}/5 =
                <strong>{incident['risk_score']}/25
                ({incident['risk_level']})</strong>.
            </p>
        </section>
        """

    mitigation_rows = ""

    for priority, (_, incident) in enumerate(
        data.sort_values(
            "risk_score",
            ascending=False,
        ).iterrows(),
        start=1,
    ):
        mitigation_rows += f"""
        <tr>
            <td>{priority}</td>
            <td>{incident['incident_id']}</td>
            <td>{incident['incident_type']}</td>
            <td>{incident['recommended_mitigations']}</td>
        </tr>
        """

    if summary["critical_risk"] > 0:
        critical_summary = (
            f"{summary['critical_risk']} incidents were assessed "
            "as Critical risk."
        )
    else:
        critical_summary = "No incidents were assessed as Critical risk."

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Cybersecurity Incident and Risk Analysis</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 40px auto;
            padding: 0 20px;
            line-height: 1.6;
            color: #222;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        h2 {{
            margin-top: 40px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }}

        h3 {{
            margin-top: 30px;
        }}

        .subtitle {{
            color: #555;
            margin-top: 0;
        }}

        .summary {{
            display: flex;
            gap: 15px;
            margin: 25px 0;
        }}

        .card {{
            border: 1px solid #ddd;
            padding: 15px 20px;
            flex: 1;
            text-align: center;
        }}

        .number {{
            font-size: 28px;
            font-weight: bold;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}

        th,
        td {{
            border: 1px solid #ddd;
            padding: 9px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #f2f2f2;
        }}

        section {{
            margin-bottom: 30px;
        }}

        img {{
            display: block;
            max-width: 100%;
            margin: 20px auto;
        }}

        .methodology {{
            background: #f7f7f7;
            padding: 15px 20px;
        }}

        .note {{
            background: #f7f7f7;
            padding: 12px 18px;
            margin: 20px 0;
        }}
    </style>
</head>

<body>

<h1>Cybersecurity Incident and Risk Analysis</h1>

<p class="subtitle">
    Analysis of simulated security logs using rule-based incident
    detection, incident investigation and qualitative cybersecurity
    risk assessment.
</p>


<h2>1. Executive Summary</h2>

<p>
    Analysis of the simulated security logs identified
    <strong>{summary['incidents']} security incidents</strong>
    from <strong>{summary['events']} events</strong>.
    {critical_summary}
    The remaining incident was assessed as Medium risk.
</p>

<p>
    The highest-priority finding involved suspicious activity
    affecting the privileged <strong>admin01</strong> account.
    A separate brute-force attack showed repeated failed
    authentication attempts followed by a successful login.
    Network reconnaissance was also detected through rapid
    probing
    of multiple destination ports.
</p>

<p>
    The analysis demonstrates an end-to-end cybersecurity workflow
    covering security log analysis, incident detection,
    investigation, risk assessment and mitigation recommendations.
</p>


<div class="summary">

    <div class="card">
        <div class="number">{summary['events']}</div>
        Events analysed
    </div>

    <div class="card">
        <div class="number">{summary['incidents']}</div>
        Incidents detected
    </div>

    <div class="card">
        <div class="number">{summary['critical_risk']}</div>
        Critical risk
    </div>

    <div class="card">
        <div class="number">{summary['medium_risk']}</div>
        Medium risk
    </div>

</div>


<h2>2. Dataset &amp; Methodology</h2>

<div class="methodology">

<p>
    The project uses simulated authentication and network security
    logs representing normal activity and deliberately injected
    suspicious behaviour.
</p>

<p>
    Deterministic detection rules identify three incident types:
    brute-force authentication, suspicious account activity and
    network port scanning.
</p>

<p>
    Detected incidents are investigated using surrounding log
    activity and user activity baselines. Each incident is then
    assessed using a qualitative 5 x 5 risk matrix.
</p>

<p>
    <strong>Risk score = Likelihood x Impact</strong>
</p>

<p>
    Scores of 1-4 are classified as Low, 5-9 as Medium,
    10-14 as High and 15-25 as Critical.
</p>

</div>


<h2>3. Incident Overview</h2>

<p>
    The table below summarises the incidents identified during
    the analysis and their resulting risk assessments.
</p>

<table>
    <thead>
        <tr>
            <th>ID</th>
            <th>Incident Type</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
        </tr>
    </thead>

    <tbody>
        {incident_rows}
    </tbody>
</table>


<h2>4. Incident Investigation</h2>

<p>
    Each detected incident was investigated using the available
    log evidence and contextual information. The findings below
    describe what the activity indicates and its potential
    security implications.
</p>

{investigation_sections}


<h2>5. Risk Prioritisation</h2>

<p>
    Incidents were prioritised using their calculated risk scores.
    The suspicious privileged-account activity represents the
    highest-priority finding because compromise of a privileged
    account could have severe consequences. The brute-force
    incident is also Critical because repeated failed logins were
    followed by a successful authentication. The port scan is
    lower priority because no successful connections were observed.
</p>

<img
    src="{risk_scores.name}"
    alt="Incident risk scores"
>

<img
    src="{risk_matrix.name}"
    alt="Security incident risk matrix"
>


<h2>6. Recommended Mitigations</h2>

<p>
    Mitigations are prioritised according to the assessed risk
    associated with each incident. Higher-risk incidents receive
    greater priority for remediation.
</p>

<table>
    <thead>
        <tr>
            <th>Priority</th>
            <th>Incident</th>
            <th>Type</th>
            <th>Recommended mitigation</th>
        </tr>
    </thead>

    <tbody>
        {mitigation_rows}
    </tbody>
</table>


<h2>7. Limitations</h2>

<ul>
    <li>
        The dataset is simulated and does not represent real
        production security activity.
    </li>

    <li>
        Detection uses deterministic rules rather than machine
        learning or statistical anomaly detection.
    </li>

    <li>
        Risk scores represent qualitative analyst judgement rather
        than statistically calculated probabilities.
    </li>

    <li>
        The available logs provide limited context compared with
        a real security monitoring environment.
    </li>
</ul>


</body>
</html>
"""

    REPORT_FILE.write_text(
        html,
        encoding="utf-8",
    )

    return REPORT_FILE


def main():
    """Generate the final security analysis report."""
    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    events, data = load_data()

    report_file = create_report(
        events,
        data,
    )

    print(f"Report generated: {report_file}")


if __name__ == "__main__":
    main()