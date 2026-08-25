# Cybersecurity Incident and Risk Analysis

A Python-based cybersecurity analysis project that detects simulated security incidents, investigates the supporting evidence, assesses cybersecurity risk and recommends prioritised mitigations.

This project demonstrates an end-to-end security analysis workflow:

- Security logs
- Incident detection
- Incident investigation
- Risk assessment
- Risk prioritisation
- Mitigation recommendations

The project uses simulated security data and does not interact with real systems.

## Project Overview

The analysis focuses on three simulated incident types:

- Brute-force authentication attacks
- Suspicious account activity
- Network port scanning

Each detected incident is investigated using the surrounding log activity and relevant contextual information. The findings are then assessed using a qualitative likelihood and impact model before appropriate mitigations are recommended.

## Key Results

The analysis identified three security incidents from the simulated dataset:

| Incident | Risk Score | Risk Level |
|---|---:|---|
| Suspicious account activity | 20/25 | Critical |
| Brute-force authentication | 16/25 | Critical |
| Network port scanning | 6/25 | Medium |

The suspicious privileged-account activity was assessed as the highest-priority risk because compromise of a privileged account could have severe consequences.

The brute-force incident was also assessed as Critical because repeated failed authentication attempts were followed by a successful login.

The network port scan was assessed as Medium because the activity was consistent with reconnaissance, but no successful connections were observed.

## Methodology

### 1. Simulated Security Logs

This project uses simulated authentication and network events representing both normal activity and deliberately injected suspicious behaviour.

The dataset contains fields such as:

- Timestamp
- Event type
- Source IP
- Username
- Authentication result
- Country
- Destination IP
- Destination port
- Protocol

### 2. Incident Detection

Deterministic detection rules identify suspicious patterns in the logs.

Examples include:

- Repeated failed authentication attempts against the same account
- Successful authentication from an unusual location or time
- Rapid connections to multiple destination ports

### 3. Incident Investigation

Detected incidents are investigated using surrounding log activity and user baselines.

The investigation aims to determine:

- What happened?
- What evidence supports the finding?
- What is the potential security implication?
- What further investigation may be required?

### 4. Risk Assessment

Each incident is assessed using a qualitative 5 x 5 risk matrix.

**Risk score = Likelihood x Impact**

| Score | Risk Level |
|---:|---|
| 1–4 | Low |
| 5–9 | Medium |
| 10–14 | High |
| 15–25 | Critical |

Likelihood and impact are scored from 1 to 5 based on the evidence available for each incident.

The scores represent qualitative analyst judgement rather than statistically calculated probabilities.

### 5. Mitigation

Recommended actions are selected based on the specific risk identified.

Examples include:

- Requiring multi-factor authentication
- Rate limiting or account lockout
- Privileged account monitoring
- Firewall restrictions
- Removing unnecessary exposed services
- Reviewing suspicious authentication activity

## Output

The final security analysis report is available in `output/security_report.html`.

The HTML report contains:

- Executive summary
- Dataset and methodology
- Incident overview
- Incident investigation
- Risk prioritisation
- Recommended mitigations
- Project limitations

## Reproducing the Analysis

Clone the repository:

```bash
git clone https://github.com/mikekent72/cybersecurity-incident-risk-analysis.git
cd cybersecurity-incident-risk-analysis
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

Run these Python files in order:

```bash
python src/data_generation.py
python src/detection.py
python src/investigation.py
python src/risk_assessment.py
python src/report.py
```

## Limitations

The main limitations are:

- The dataset is simulated and does not represent real production security activity.
- Detection uses deterministic rules rather than machine learning or statistical anomaly detection.
- The risk scores represent qualitative analyst judgement rather than statistically calculated probabilities.
- The available logs provide limited context compared with a real security monitoring environment.

## Technologies

- Python
- pandas
- matplotlib