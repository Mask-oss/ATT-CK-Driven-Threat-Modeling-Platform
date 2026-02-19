# ATT&CK-Driven Threat Modeling Platform

> *"If you know the enemy and know yourself, you need not fear the result of a hundred battles."*
> — Sun Tzu, The Art of War

A CLI-based threat modeling tool that operationalizes the first principle of *The Art of War* into measurable, decision-grade cybersecurity analysis.

---

## 🧭 Philosophical Foundation

This tool is inspired by **Principle #1 of The Art of War**:

> **"Know yourself and know your enemy"** (知彼知己)

Sun Tzu's insight was not about strength — it was about **reducing uncertainty before conflict**. Victory belongs to whoever eliminates surprise through intelligence and self-awareness.

In cybersecurity, this translates directly to:

| Sun Tzu | Cybersecurity |
|---------|--------------|
| Know yourself | Asset inventory, attack surface, control maturity |
| Know your enemy | Threat actors, TTPs (Tactics, Techniques, Procedures) |
| Reduce uncertainty | Quantified risk — Inherent vs. Residual |
| Strategic decision | Prioritized, evidence-based defensive actions |

A security program that cannot answer *"who is targeting us, and how?"* is not defense — it is reaction.

---

## 🎯 What This Tool Does

This platform turns a philosophical principle into an **actionable security decision workflow**:

1. **Asset Profile** — model what you own and its exposure (Know Yourself)
2. **Threat Actor Mapping** — select an adversary and load their ATT&CK technique profile (Know Your Enemy)
3. **Coverage Matrix** — assess Prevent / Detect / Respond coverage per technique
4. **Risk Scoring** — compute Inherent Risk vs. Residual Risk with a transparent, documented heuristic model
5. **Recommendations** — prioritized defensive actions with CIS Controls mapping and evidence/log sources
6. **Export** — JSON report for dashboards, further analysis, or academic documentation

---

## 🖥️ Demo

```
╔════════════════════════════════════════════════════════════════════╗
║     ATT&CK-Driven Threat Modeling Platform (MVP++)                 ║
║     "Know Yourself and Know Your Enemy" — Sun Tzu                  ║
╚════════════════════════════════════════════════════════════════════╝

MODULE 1: Asset Profile — Know Yourself
  Asset: HR Database | Type: Database Server | Exposure: Internal Only
  Data Sensitivity: Confidential | Control Maturity: 0.5 (Medium)

MODULE 2: Threat Actor — Know Your Enemy
  Selected: APT (Nation-State) — Espionage / Sabotage | Sophistication: High

MODULE 3: Coverage Matrix
  ID         Technique                   Tactic              Prevent  Detect  Respond
  T1190      Exploit Public-Facing App   Initial Access        ✓        ✓        ✓
  T1003      OS Credential Dumping       Credential Access     ✓        ✓        ✓
  ...

MODULE 4: Risk Scoring
  Technique                   InhLik   Impact  InhRisk  ResRisk  Level
  OS Credential Dumping         0.88     0.84     0.74     0.44    MED
  ...

MODULE 5: Recommendations
   HIGH — Prioritize immediately
   MED  — Near-term hardening plan
```

---

## 🚀 Quick Start

**Requirements:** Python 3.7+, no external dependencies.

```bash
# Clone the repository/Mask-oss/attack-threat-modeling.git
cd attack-threat-modeling

# Run the platform
python3 threat_modeling_platform.py
```

Follow the interactive prompts to model your asset and threat actor.

---

## 🧱 Architecture

```
threat_modeling_platform.py
│
├── Module 1: Asset Profile
│   ├── Asset type (Web App, DB, Endpoint, Cloud...)
│   ├── Exposure level (Internet-Facing, DMZ, Internal)
│   ├── Data sensitivity (Public → Top Secret)
│   └── Control maturity (0.2 / 0.5 / 0.8)
│
├── Module 2: Threat Actor Mapping
│   ├── Cybercrime (Financial, Medium sophistication)
│   ├── APT / Nation-State (Espionage, High sophistication)
│   └── Insider Threat (Revenge/Financial, Low-Medium)
│
├── Module 3: Coverage Matrix + Tactic Heatmap
│   ├── Per-technique: Prevent / Detect / Respond
│   └── Per-tactic coverage % with ASCII heatmap
│
├── Module 4: Risk Scoring Engine
│   ├── Inherent Risk = Likelihood × Impact
│   ├── Control Effectiveness = f(maturity, P, D, R)
│   └── Residual Risk = Inherent Risk × (1 − Effectiveness)
│
└── Module 5: Recommendations + Export
    ├── Risk-ranked recommendations (HIGH / MED / LOW)
    ├── CIS Controls v8 Safeguard mapping (illustrative)
    ├── Evidence & log sources per technique
    ├── Threat Narrative (top residual risk scenario)
    └── JSON export
```

---

## 📐 Risk Model

The scoring model is a **transparent, documented heuristic** — not a mandated standard formula. It is conceptually aligned with NIST SP 800-30.

```
Inherent Likelihood  = Actor_Likelihood × Asset_Exposure_Factor
Impact               = Data_Sensitivity × Asset_Type_Factor × 0.70
Inherent Risk        = Inherent_Likelihood × Impact

Control_Effectiveness = Maturity × (0.45 × Prevent + 0.35 × Detect + 0.20 × Respond)

Residual Risk        = Inherent_Risk × (1 − Control_Effectiveness)
```

**Why these weights (0.45 / 0.35 / 0.20)?**

- **Prevent (0.45):** Strongest reducer — blocks the attack before impact occurs.
- **Detect (0.35):** Reduces dwell time and enables response, but does not stop the initial event.
- **Respond (0.20):** Limits blast radius and recovery time, but typically activates after detection.

These are project-specific estimates. For production environments, calibrate using historical incident data or purple team results.

> ⚠️ **Coverage ≠ Effectiveness.** 100% technique coverage means controls *exist*. Low control maturity means they may not be enforced, tuned, or tested — and residual risk remains high.

---

## 🗺️ Framework Alignment

| Framework | Role in This Tool |
|-----------|------------------|
| **MITRE ATT&CK** | Technique library, adversary TTPs, tactic taxonomy |
| **NIST SP 800-30** | Risk assessment concepts: inherent/residual risk, likelihood, impact |
| **NIST CSF 2.0** | Governs the *Identify* and *Govern* functions |
| **CIS Controls v8** | Illustrative Safeguard IDs mapped to each technique |

---

## 📂 Output: JSON Report

When exported, the report includes:

```json
{
  "timestamp": "2026-02-19T12:00:00",
  "asset": { "name": "HR Database", "type": "Database Server", ... },
  "threat_actor": "APT (Nation-State)",
  "overall_coverage_pd_pct": 100.0,
  "tactic_coverage": { "Initial Access": { "coverage_pd_pct": 100.0, ... } },
  "tactic_risk": { "Credential Access": { "avg_inherent_risk": 0.74, "avg_residual_risk": 0.44 } },
  "risk_items": [ ... ],
  "recommendations_high": [ ... ],
  "notes": [
    "Risk scoring model is a project-specific quantitative approximation.",
    "Inherent vs residual aligns with NIST SP 800-30 concepts (methodology), not a mandated formula."
  ]
}
```

---

## 📚 References

| Source | Link |
|--------|------|
| MITRE ATT&CK | https://attack.mitre.org |
| NIST SP 800-30 Rev.1 | https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final |
| NIST CSF 2.0 | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf |
| CIS Controls v8 | https://www.cisecurity.org/controls/v8 |
| Sun Tzu — The Art of War | Chapter 3: Strategic Attack |

---

## 🔭 Roadmap

- [ ] Multi-asset analysis (analyze several assets in one session)
- [ ] HTML / PDF report export
- [ ] ATT&CK version tagging (v14, v15...)
- [ ] Configurable scoring weights per environment
- [ ] YAML/JSON threat actor profiles (extensible dataset)
- [ ] Interactive coverage gap wizard

---

## 📄 License

MIT License — see `LICENSE` for details.

---

*Built on Sun Tzu's first principle. Grounded in MITRE ATT&CK and NIST frameworks.*
