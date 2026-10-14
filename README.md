# IdentityOS — Enterprise Identity & Access Governance

**IdentityOS** is a self-service Identity Governance & Administration (IGA) and IAM lifecycle automation dashboard. It streamlines **Joiner, Mover, and Leaver (JML)** processes, multi-cloud entitlement provisioning, real-time risk scoring, and continuous regulatory compliance (SOX 404, ISO 27001, GDPR).

---

## Key Features

- **Lifecycle Automation (JML)**: End-to-end orchestration for Joiners, Movers, and Leavers with automated access revocation and scheduling.
- **AI Identity Assistant**: Natural language automation interface with pre-built playbooks for rapid role provisioning and access review.
- **Multi-Cloud Connector Health**: Real-time status indicators across Active Directory, Microsoft Entra ID, Okta, AWS Identity Center, and Splunk SIEM.
- **Approvals & Governance Queue**: Contextual review cards with entitlement diffs, TTL controls, and 1-click approvals.
- **Risk Analytics & Anomaly Detection**: 30-day identity risk scoring trends, MFA anomaly detection, and dormant account monitoring.
- **Immutable Audit Trail**: Filterable event log by timestamp, event category, actor, and severity.
- **Segregation of Duties (SoD) & Certifications**: Automated policy conflict detection and recertification campaign tracking.
- **Enterprise Design System**: High-density Classic Enterprise theme (Corporate Navy & Light Slate) with full **Dark Slate Enterprise** mode support.

---

## Tech Stack

- **Frontend**: Semantic HTML5, Vanilla JavaScript (ES6+), Vanilla CSS Custom Properties
- **Visualization**: [Chart.js 4.4](https://www.chartjs.org/)
- **Typography**: Inter & JetBrains Mono (Google Fonts)

---

## Getting Started

No build tools or package managers required. Simply clone the repository and run locally:

```bash
# Clone the repository
git clone <your-repository-url>
cd iam-dashboard

# Start a local static server
python3 -m http.server 8080
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

---

## Project Structure

```
├── index.html       # Single-page dashboard application layout
├── style.css        # Enterprise design system (tokens, components, light/dark themes)
├── app.js           # Interactive controller, Chart.js integrations, search, AI logic
├── README.md        # Documentation
└── .gitignore       # Git ignore rules
```

---

## License

MIT License.
