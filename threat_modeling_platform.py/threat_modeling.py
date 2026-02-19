#!/usr/bin/env python3
"""
ATT&CK-Driven Threat Modeling Platform (MVP++)
Principle: "Know yourself and know your enemy" — Sun Tzu

What this tool does (academic framing):
- Models an asset ("Know yourself") + a threat actor ("Know your enemy") using a curated ATT&CK subset.
- Builds a technique coverage matrix (Prevent/Detect/Respond).
- Estimates Inherent Risk vs Residual Risk using a transparent, documented heuristic model inspired by
  NIST SP 800-30 risk assessment concepts (methodology, not a mandated formula).
- Outputs per-tactic coverage + per-tactic risk summaries and produces prioritized recommendations.
- Optionally exports a JSON report for further analysis / dashboards.

References (for your thesis/report citations):
- NIST SP 800-30 Rev.1 (Risk Assessment): https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
- NIST CSF 2.0: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- MITRE ATT&CK: https://attack.mitre.org
- CIS Controls v8: https://www.cisecurity.org/controls/v8
"""

import json
import os
import re
from datetime import datetime
from collections import defaultdict


def banner():
    print("ATT&CK-Driven Threat Modeling Platform (MVP++)")
    print('"Know Yourself and Know Your Enemy" — Sun Tzu')
    print("-" * 78)


def section(title: str):
    print("\n" + "-" * 78)
    print(f"{title}")
    print("-" * 78 + "\n")


def ask(prompt: str, options=None) -> str:
    if options:
        if prompt:
            print(prompt)
        for i, opt in enumerate(options, 1):
            print(f"  [{i}] {opt}")
        while True:
            try:
                choice = int(input("\nChoose a number: "))
                if 1 <= choice <= len(options):
                    return choice - 1
            except ValueError:
                pass
            print("Invalid choice, try again.")
    return input(f"{prompt}: ").strip()


def yesno(prompt: str) -> bool:
    v = ask(prompt)
    return v.strip().lower() in ["yes", "y", "1", "true", "ok"]


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def sanitize_filename(s: str, max_len: int = 60) -> str:
    s = s.strip()
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^A-Za-z0-9_\-]+", "", s)
    return (s[:max_len] if s else "asset")


def bar(pct: float, width: int = 18) -> str:
    filled = int(round((pct / 100.0) * width))
    filled = max(0, min(width, filled))
    return "█" * filled + "░" * (width - filled)


#
# Curated ATT&CK subset (MVP dataset)

THREAT_ACTORS = {
    "Cybercrime": {
        "description": "Profit-motivated groups",
        "motivation": "Financial",
        "sophistication": "Medium",
        "techniques": [
            {"id": "T1566", "name": "Phishing",                    "tactic": "Initial Access",      "likelihood": 0.90},
            {"id": "T1486", "name": "Data Encrypted (Ransomware)", "tactic": "Impact",              "likelihood": 0.80},
            {"id": "T1110", "name": "Brute Force",                "tactic": "Credential Access",   "likelihood": 0.70},
            {"id": "T1078", "name": "Valid Accounts",             "tactic": "Persistence",         "likelihood": 0.70},
            {"id": "T1041", "name": "Exfiltration Over C2",       "tactic": "Exfiltration",        "likelihood": 0.60},
            {"id": "T1055", "name": "Process Injection",          "tactic": "Defense Evasion",     "likelihood": 0.50},
        ],
    },
    "APT (Nation-State)": {
        "description": "Highly resourced, long-term campaigns (espionage/sabotage)",
        "motivation": "Espionage / Sabotage",
        "sophistication": "High",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing App",   "tactic": "Initial Access",      "likelihood": 0.80},
            {"id": "T1071", "name": "Application Layer Protocol",  "tactic": "Command and Control", "likelihood": 0.90},
            {"id": "T1003", "name": "OS Credential Dumping",       "tactic": "Credential Access",   "likelihood": 0.80},
            {"id": "T1021", "name": "Remote Services",             "tactic": "Lateral Movement",    "likelihood": 0.80},
            {"id": "T1083", "name": "File & Directory Discovery",  "tactic": "Discovery",           "likelihood": 0.70},
            {"id": "T1005", "name": "Data from Local System",      "tactic": "Collection",          "likelihood": 0.70},
            {"id": "T1070", "name": "Indicator Removal",           "tactic": "Defense Evasion",     "likelihood": 0.80},
            {"id": "T1195", "name": "Supply Chain Compromise",     "tactic": "Initial Access",      "likelihood": 0.50},
        ],
    },
    "Insider Threat": {
        "description": "A trusted user misusing legitimate privileges",
        "motivation": "Revenge / Financial",
        "sophistication": "Low-Medium",
        "techniques": [
            {"id": "T1078", "name": "Valid Accounts",                  "tactic": "Initial Access", "likelihood": 1.00},
            {"id": "T1048", "name": "Exfiltration Over Alt Protocol",  "tactic": "Exfiltration",   "likelihood": 0.70},
            {"id": "T1485", "name": "Data Destruction",                "tactic": "Impact",         "likelihood": 0.60},
            {"id": "T1530", "name": "Data from Cloud Storage",         "tactic": "Collection",     "likelihood": 0.70},
            {"id": "T1087", "name": "Account Discovery",               "tactic": "Discovery",      "likelihood": 0.50},
        ],
    },
}

ASSET_RISK_MULTIPLIER = {
    "Web Application":       1.30,
    "Database Server":       1.50,
    "Endpoint / Laptop":     1.00,
    "Internal Server":       1.10,
    "Cloud Infrastructure":  1.40,
}

EXPOSURE_MULTIPLIER = {
    "Internet-Facing (Public)": 1.50,
    "DMZ":                      1.20,
    "Internal Only":            1.00,
}

DATA_SENSITIVITY = {
    "Public":       0.20,
    "Internal":     0.50,
    "Confidential": 0.80,
    "Top Secret":   1.00,
}

# Controls mapping (MVP): includes illustrative CIS Safeguard IDs + evidence/log sources for auditability.
# NOTE: Safeguard IDs below are examples for academic demonstration and should be validated for a formal thesis.
CONTROLS = {
    "T1566": {
        "prevent": "Secure email gateway + DMARC/SPF/DKIM",
        "detect": "Sandbox/detonation + user-reported phishing queue",
        "respond": "Block sender/domain + awareness + reset creds if needed",
        "cis_safeguards": ["9.1", "9.2", "14.2"],
        "evidence": {
            "log_sources": ["Email gateway logs", "Proxy logs", "SIEM alerts"],
            "detection_idea": "Spike in similar subjects / suspicious URLs / new sender domains",
        },
    },
    "T1486": {
        "prevent": "Offline/immutable backups + EDR ransomware protection",
        "detect": "FIM + high-entropy rename/write patterns",
        "respond": "Isolate host + restore + IR runbook",
        "cis_safeguards": ["11.1", "11.2", "10.1"],
        "evidence": {
            "log_sources": ["EDR telemetry", "File server logs"],
            "detection_idea": "Mass file modifications + ransom note patterns",
        },
    },
    "T1110": {
        "prevent": "MFA + lockout + rate limiting",
        "detect": "Failed login bursts + risky sign-in",
        "respond": "Block IP + force reset + investigate",
        "cis_safeguards": ["6.3", "6.7"],
        "evidence": {
            "log_sources": ["Auth logs", "IdP logs"],
            "detection_idea": "Many failures across accounts or a single account rapidly",
        },
    },
    "T1078": {
        "prevent": "PAM + least privilege + strong MFA for privileged roles",
        "detect": "Anomalous login context (new device/geo/odd hour)",
        "respond": "Disable account + revoke sessions/tokens + IR triage",
        "cis_safeguards": ["6.1", "6.5", "6.8"],
        "evidence": {
            "log_sources": ["IdP logs", "VPN logs", "EDR telemetry"],
            "detection_idea": "Privileged access from unusual context",
        },
    },
    "T1041": {
        "prevent": "Egress filtering + DLP + outbound allow-lists",
        "detect": "NetFlow/NTA anomalies + unusual long-lived connections",
        "respond": "Block C2 + isolate host + collect evidence",
        "cis_safeguards": ["12.4", "13.7"],
        "evidence": {
            "log_sources": ["Firewall logs", "NetFlow", "DNS logs"],
            "detection_idea": "Unexpected outbound volume to rare domains",
        },
    },
    "T1055": {
        "prevent": "EDR with memory protection + ASR rules (where applicable)",
        "detect": "Injection indicators + suspicious module loads",
        "respond": "Quarantine + memory dump + triage",
        "cis_safeguards": ["10.4", "10.6"],
        "evidence": {
            "log_sources": ["EDR telemetry", "Sysmon (if enabled)"],
            "detection_idea": "Process injection patterns / abnormal process trees",
        },
    },
    "T1190": {
        "prevent": "WAF + secure SDLC + regular patching",
        "detect": "WAF alerts + web log anomaly patterns",
        "respond": "Patch + rotate secrets + integrity checks",
        "cis_safeguards": ["4.8", "16.11"],
        "evidence": {
            "log_sources": ["WAF logs", "Web server logs"],
            "detection_idea": "Exploit probes, unusual parameters, traversal patterns",
        },
    },
    "T1071": {
        "prevent": "Proxy controls + TLS inspection (policy-dependent)",
        "detect": "DNS/HTTP anomalies + beaconing patterns",
        "respond": "Block domains + hunt endpoints + IR",
        "cis_safeguards": ["13.1", "13.6"],
        "evidence": {
            "log_sources": ["Proxy logs", "DNS logs"],
            "detection_idea": "Regular beaconing / rare domains / unusual user-agents",
        },
    },
    "T1003": {
        "prevent": "Credential Guard/LSA hardening + OS hardening",
        "detect": "LSASS access alerts + suspicious memory reads",
        "respond": "Reset creds + isolate + lateral movement hunt",
        "cis_safeguards": ["6.2", "10.7"],
        "evidence": {
            "log_sources": ["EDR telemetry", "Windows Security logs"],
            "detection_idea": "Unexpected processes touching LSASS",
        },
    },
    "T1021": {
        "prevent": "Segmentation + restrict admin protocols",
        "detect": "Lateral movement signals (RDP/SMB spikes)",
        "respond": "Isolate segment + disable exposed admin services",
        "cis_safeguards": ["12.2", "12.8"],
        "evidence": {
            "log_sources": ["Firewall logs", "Windows logs"],
            "detection_idea": "New remote service usage between peers",
        },
    },
    "T1083": {
        "prevent": "Least privilege + limit broad directory reads",
        "detect": "Discovery tool patterns + file auditing",
        "respond": "Review access + correlate with other TTPs",
        "cis_safeguards": ["6.4", "8.2"],
        "evidence": {
            "log_sources": ["EDR telemetry", "File server logs"],
            "detection_idea": "Burst of directory listing / discovery tooling",
        },
    },
    "T1005": {
        "prevent": "DLP + encryption at rest + strict access controls",
        "detect": "Unusual reads/exports + DB auditing",
        "respond": "Revoke access + investigate + contain exfil path",
        "cis_safeguards": ["3.4", "6.6"],
        "evidence": {
            "log_sources": ["DB audit logs", "EDR telemetry"],
            "detection_idea": "Large exports or unusual SELECT patterns",
        },
    },
    "T1070": {
        "prevent": "Centralized/immutable logging + restrict log admin rights",
        "detect": "Log clearing/deletion alerts + service stop events",
        "respond": "Forensics + hunt + restore logging where possible",
        "cis_safeguards": ["8.6", "8.7"],
        "evidence": {
            "log_sources": ["SIEM", "Windows logs"],
            "detection_idea": "Event log cleared / audit service stopped",
        },
    },
    "T1195": {
        "prevent": "Vendor risk management + signed builds + SBOM checks",
        "detect": "Integrity verification + unusual update patterns",
        "respond": "Isolate impacted systems + rollback/patch",
        "cis_safeguards": ["15.1", "15.2"],
        "evidence": {
            "log_sources": ["Software inventory", "CI/CD logs"],
            "detection_idea": "Unexpected package updates / signature mismatch",
        },
    },
    "T1048": {
        "prevent": "Egress filtering + DLP policies",
        "detect": "Unusual outbound protocol usage",
        "respond": "Block channel + HR/legal workflow if insider",
        "cis_safeguards": ["13.7", "3.12"],
        "evidence": {
            "log_sources": ["Firewall logs", "Proxy logs"],
            "detection_idea": "New protocols/ports or rare destinations",
        },
    },
    "T1485": {
        "prevent": "RBAC + backups + protected delete operations",
        "detect": "Mass delete alerts + unusual admin actions",
        "respond": "Restore + preserve evidence + HR/legal as required",
        "cis_safeguards": ["11.1", "6.8"],
        "evidence": {
            "log_sources": ["File server logs", "Cloud audit logs"],
            "detection_idea": "Rapid deletions or privileged destructive actions",
        },
    },
    "T1530": {
        "prevent": "CSPM + strong IAM + least privilege for cloud storage",
        "detect": "Cloud audit logging (CASB/CloudTrail-like)",
        "respond": "Revoke tokens + review sharing permissions",
        "cis_safeguards": ["15.4", "6.3"],
        "evidence": {
            "log_sources": ["Cloud audit logs"],
            "detection_idea": "Large downloads / new sharing links / unusual IPs",
        },
    },
    "T1087": {
        "prevent": "Least privilege + restrict directory query rights",
        "detect": "AD/LDAP query monitoring",
        "respond": "Review account activity + hunt",
        "cis_safeguards": ["6.4", "8.2"],
        "evidence": {
            "log_sources": ["AD logs", "EDR telemetry"],
            "detection_idea": "Enumeration patterns / repeated directory queries",
        },
    },
}


# Module 1: Asset Profile (Know Yourself)

def module_asset_profile():
    section("MODULE 1: Asset Profile — Know Yourself")

    asset_name = ask("Asset name (e.g., HR Database)") or "Unknown Asset"

    asset_types = list(ASSET_RISK_MULTIPLIER.keys())
    asset_type = asset_types[ask("Asset type:", asset_types)]

    exposures = list(EXPOSURE_MULTIPLIER.keys())
    exposure = exposures[ask("Exposure level:", exposures)]

    sensitivities = list(DATA_SENSITIVITY.keys())
    sensitivity = sensitivities[ask("Data sensitivity:", sensitivities)]

    maturity_options = ["0.2 (Low)", "0.5 (Medium)", "0.8 (Good)"]
    maturity_choice = ask(
        "Approx. control maturity (how well controls are implemented/operational):",
        maturity_options
    )
    control_maturity = [0.2, 0.5, 0.8][maturity_choice]

    asset = {
        "name": asset_name,
        "type": asset_type,
        "exposure": exposure,
        "sensitivity": sensitivity,
        "control_maturity": control_maturity,
        "risk_multiplier": ASSET_RISK_MULTIPLIER[asset_type] * EXPOSURE_MULTIPLIER[exposure],
        "impact_base": DATA_SENSITIVITY[sensitivity],
    }

    print("\nAsset registered:")
    print(f"  • Name:     {asset_name}")
    print(f"  • Type:     {asset_type}")
    print(f"  • Exposure: {exposure}")
    print(f"  • Data:     {sensitivity}")
    print(f"  • Maturity: {control_maturity}")

    return asset


# 
# Module 2: Threat Actor (Know Your Enemy)

def module_threat_actor():
    section("MODULE 2: Threat Actor Mapping — Know Your Enemy")

    actors = list(THREAT_ACTORS.keys())
    for i, a in enumerate(actors, 1):
        info = THREAT_ACTORS[a]
        print(f"  [{i}] {a}")
        print(f"      {info['description']}")
        print(f"      Motivation: {info['motivation']} | Sophistication: {info['sophistication']}\n")

    actor_name = actors[ask("Select a threat actor:", actors)]
    actor = THREAT_ACTORS[actor_name]

    print(f"\nSelected actor: {actor_name}")
    print(f"\nTechniques in this curated profile ({len(actor['techniques'])}):")
    for t in actor["techniques"]:
        print(f"  [{t['id']}] {t['name']} — {t['tactic']}")

    return actor_name, actor



# Module 3: Coverage Matrix + Per-Tactic Heatmap

def module_coverage_matrix(actor):
    section("MODULE 3: Technique Coverage Matrix")

    techniques = actor["techniques"]
    results = []

    header = f"{'ID':<10} {'Technique':<35} {'Tactic':<24} {'Prevent':<8} {'Detect':<8} {'Respond':<8}"
    print(header)
    print(f"{'-'*9} {'-'*34} {'-'*23} {'-'*7} {'-'*7} {'-'*7}")

    tactic_stats = defaultdict(lambda: {"total": 0, "p": 0, "d": 0, "r": 0, "pd": 0})

    for t in techniques:
        tid = t["id"]
        ctrl = CONTROLS.get(tid, {})

        has_p = bool(ctrl.get("prevent"))
        has_d = bool(ctrl.get("detect"))
        has_r = bool(ctrl.get("respond"))

        p_sym = "  ✓   " if has_p else "  ✗   "
        d_sym = "  ✓   " if has_d else "  ✗   "
        r_sym = "  ✓   " if has_r else "  ✗   "

        print(f"{tid:<10} {t['name']:<35} {t['tactic']:<24} {p_sym} {d_sym} {r_sym}")

        results.append({
            "technique": t,
            "has_prevent": has_p,
            "has_detect": has_d,
            "has_respond": has_r,
            "controls": ctrl,
        })

        ts = tactic_stats[t["tactic"]]
        ts["total"] += 1
        ts["p"] += int(has_p)
        ts["d"] += int(has_d)
        ts["r"] += int(has_r)
        ts["pd"] += int(has_p and has_d)

    covered_pd = sum(1 for r in results if r["has_prevent"] and r["has_detect"])
    coverage_pct = (covered_pd / len(results)) * 100 if results else 0.0

    print(f"\nOverall ATT&CK Coverage (Prevent+Detect): {coverage_pct:.0f}%")

    section("Per-Tactic Coverage Heatmap (Prevent+Detect)")
    print(f"{'Tactic':<26} {'P+D%':>6}  {'Heat':<20}  {'P':>3} {'D':>3} {'R':>3} {'Tot':>4}")
    print(f"{'-'*25} {'-'*6}  {'-'*20}  {'-'*3} {'-'*3} {'-'*3} {'-'*4}")

    for tactic, s in sorted(tactic_stats.items(), key=lambda kv: kv[0]):
        pct = (s["pd"] / s["total"] * 100) if s["total"] else 0.0
        print(f"{tactic:<26} {pct:>5.0f}%  {bar(pct, 18)}  {s['p']:>3} {s['d']:>3} {s['r']:>3} {s['total']:>4}")

    return results, tactic_stats, coverage_pct


#
# Module 4: Risk Model (Inherent vs Residual)

def calc_control_effectiveness(asset, has_prevent, has_detect, has_respond):
    """
    Control Effectiveness Model (Project-specific, documented)

    Why weights (0.45 / 0.35 / 0.20)?
    - Prevent (0.45): strongest direct reducer of attack success probability (blocks/contains early).
    - Detect  (0.35): reduces dwell time and increases chance of catching the event, but may not stop it.
    - Respond (0.20): mostly limits blast radius and time-to-recover; it matters, but typically after detection.

    These weights are NOT a standard and are not claimed as "NIST formula".
    They are a transparent heuristic aligned with the residual-risk concept:
    Residual Risk = Inherent Risk × (1 - Control Effectiveness).

    For thesis-grade rigor, you can:
    - calibrate weights using historical incident metrics / purple-team results,
    - or make weights configurable per environment/system.
    """
    m = asset["control_maturity"]  # 0..1: how well controls are implemented/operational
    w_prevent, w_detect, w_respond = 0.45, 0.35, 0.20

    eff = 0.0
    eff += (w_prevent * m) if has_prevent else 0.0
    eff += (w_detect  * m) if has_detect  else 0.0
    eff += (w_respond * m) if has_respond else 0.0
    return clamp01(eff)


def module_risk_scoring(asset, coverage_results):
    section("MODULE 4: Risk Scoring (Inherent vs Residual)")

    print(f"{'Technique':<33} {'InhLik':>7} {'Impact':>7} {'InhRisk':>8} {'ResRisk':>8} {'Level':<8}")
    print(f"{'-'*32} {'-'*7} {'-'*7} {'-'*8} {'-'*8} {'-'*7}")

    risk_items = []
    tactic_risk = defaultdict(lambda: {"inh_sum": 0.0, "res_sum": 0.0, "count": 0})

    for r in coverage_results:
        t = r["technique"]

        # Inherent likelihood: actor likelihood × asset exposure factor (clamped)
        inh_likelihood = clamp01(t["likelihood"] * asset["risk_multiplier"])

        # Impact: data sensitivity × asset factor (clamped)
        impact = clamp01(asset["impact_base"] * asset["risk_multiplier"] * 0.70)

        inherent_risk = inh_likelihood * impact

        # Residual risk: reduced by control effectiveness
        eff = calc_control_effectiveness(asset, r["has_prevent"], r["has_detect"], r["has_respond"])
        residual_risk = inherent_risk * (1.0 - eff)

        if residual_risk >= 0.50:
            level = "HIGH"
        elif residual_risk >= 0.25:
            level = "MED"
        else:
            level = "LOW"

        print(f"{t['name']:<33} {inh_likelihood:>7.2f} {impact:>7.2f} {inherent_risk:>8.2f} {residual_risk:>8.2f} {level}")

        risk_items.append({
            "id": t["id"],
            "name": t["name"],
            "tactic": t["tactic"],
            "inherent_likelihood": inh_likelihood,
            "impact": impact,
            "inherent_risk": inherent_risk,
            "control_effectiveness": eff,
            "residual_risk": residual_risk,
            "covered_pd": bool(r["has_prevent"] and r["has_detect"]),
            "has_prevent": r["has_prevent"],
            "has_detect": r["has_detect"],
            "has_respond": r["has_respond"],
            "controls": r["controls"],
        })

        tr = tactic_risk[t["tactic"]]
        tr["inh_sum"] += inherent_risk
        tr["res_sum"] += residual_risk
        tr["count"] += 1

    section("Per-Tactic Risk Summary")
    print(f"{'Tactic':<26} {'AvgInh':>10} {'AvgRes':>10} {'Count':>7}")
    print(f"{'-'*25} {'-'*10} {'-'*10} {'-'*7}")
    for tactic, s in sorted(tactic_risk.items(), key=lambda kv: kv[0]):
        avg_inh = (s["inh_sum"] / s["count"]) if s["count"] else 0.0
        avg_res = (s["res_sum"] / s["count"]) if s["count"] else 0.0
        print(f"{tactic:<26} {avg_inh:>10.2f} {avg_res:>10.2f} {s['count']:>7}")

    return sorted(risk_items, key=lambda x: x["residual_risk"], reverse=True), tactic_risk


# Module 5: Recommendations + Export

def module_recommendations_and_report(risk_items, asset, actor_name, coverage_pct, tactic_stats, tactic_risk):
    section("MODULE 5: Recommendations (Residual-Risk Driven)")

    high = [r for r in risk_items if r["residual_risk"] >= 0.50]
    med  = [r for r in risk_items if 0.25 <= r["residual_risk"] < 0.50]
    low  = [r for r in risk_items if r["residual_risk"] < 0.25]

    # Explain potential confusion: 100% coverage but still high residual risk
    if coverage_pct >= 95 and any(r["residual_risk"] >= 0.50 for r in risk_items):
        print("Note (Coverage vs Residual Risk):")
        print("- Coverage means the presence of defined controls for each technique (Prevent/Detect/Respond).")
        print("- It does NOT measure operational strength. Low control maturity keeps residual risk high even with full coverage.")
        print("- Reduce residual risk by improving maturity/effectiveness (e.g., enforced MFA, tuned WAF, centralized logging, tested IR).\n")

    def print_item(r):
        ctrl = r.get("controls") or {}
        cis = ctrl.get("cis_safeguards", [])
        ev  = ctrl.get("evidence", {}) or {}
        rr  = r["residual_risk"]

        print(f"\n  [{r['id']}] {r['name']} — {r['tactic']}")
        print(f"    Inherent: {r['inherent_risk']:.2f} | Residual: {rr:.2f} | Eff: {r['control_effectiveness']:.2f}")

        if ctrl:
            print(f"    ▸ Prevent:  {ctrl.get('prevent','—')}")
            print(f"    ▸ Detect:   {ctrl.get('detect','—')}")
            print(f"    ▸ Respond:  {ctrl.get('respond','—')}")
        if cis:
            print(f"    CIS Safeguards (illustrative): {', '.join(cis)}")
        if ev:
            logs = ev.get("log_sources", [])
            idea = ev.get("detection_idea", "")
            if logs:
                print(f"    Evidence/Logs: {', '.join(logs)}")
            if idea:
                print(f"    Detection idea: {idea}")

    if high:
        print("HIGH Residual Risk — Prioritize immediately:")
        for r in high[:8]:
            print_item(r)
    else:
        print("No HIGH residual risks under the current model.")

    if med:
        print("\nMED Residual Risk — Near-term hardening plan:")
        for r in med[:10]:
            print(f"  • [{r['id']}] {r['name']} ({r['tactic']}) — ResRisk: {r['residual_risk']:.2f}")

    section("Threat Narrative (Top Residual Risk)")
    top = risk_items[0] if risk_items else None
    if top:
        print("Most probable scenario (by top Residual Risk):\n")
        print(f"  Threat Actor: {actor_name}")
        print(f"  Asset: '{asset['name']}' ({asset['type']}, {asset['exposure']})")
        print(f"  Technique: {top['name']} [{top['id']}] — {top['tactic']}")
        print(f"  Residual Risk: {top['residual_risk']:.2f}")
        print("\n  Action: put this scenario into Detection backlog + Incident Response playbook testing.")

    section("Executive Summary")
    total = len(risk_items)
    covered_pd = sum(1 for r in risk_items if r["covered_pd"])

    print(f"  Asset:                   {asset['name']}")
    print(f"  Threat Actor:            {actor_name}")
    print(f"  Techniques assessed:     {total}")
    print(f"  Covered (Prevent+Detect): {covered_pd}")
    print(f"  Coverage (P+D):          {coverage_pct:.0f}%")
    print(f"  Control Maturity (0..1): {asset['control_maturity']}")
    print("  *Coverage ≠ Effectiveness (presence of controls does not imply operational strength)")
    print(f"  HIGH Residual Risks:     {len(high)}")
    print(f"  MED Residual Risks:      {len(med)}")
    print(f"  LOW Residual Risks:      {len(low)}")

    if yesno("Export report as JSON? (yes/no)"):
        report = {
            "timestamp": datetime.now().isoformat(),
            "asset": asset,
            "threat_actor": actor_name,
            "overall_coverage_pd_pct": round(coverage_pct, 2),
            "tactic_coverage": {
                tactic: {
                    "total": s["total"],
                    "prevent": s["p"],
                    "detect": s["d"],
                    "respond": s["r"],
                    "prevent_detect": s["pd"],
                    "coverage_pd_pct": round((s["pd"] / s["total"] * 100) if s["total"] else 0.0, 2),
                } for tactic, s in tactic_stats.items()
            },
            "tactic_risk": {
                tactic: {
                    "avg_inherent_risk": round((s["inh_sum"] / s["count"]) if s["count"] else 0.0, 4),
                    "avg_residual_risk": round((s["res_sum"] / s["count"]) if s["count"] else 0.0, 4),
                    "count": s["count"],
                } for tactic, s in tactic_risk.items()
            },
            "risk_items": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "tactic": r["tactic"],
                    "inherent_likelihood": r["inherent_likelihood"],
                    "impact": r["impact"],
                    "inherent_risk": r["inherent_risk"],
                    "control_effectiveness": r["control_effectiveness"],
                    "residual_risk": r["residual_risk"],
                    "has_prevent": r["has_prevent"],
                    "has_detect": r["has_detect"],
                    "has_respond": r["has_respond"],
                    "covered_pd": r["covered_pd"],
                    "controls": r.get("controls", {}),
                } for r in risk_items
            ],
            "recommendations_high": [
                {"id": r["id"], "name": r["name"], "tactic": r["tactic"], "controls": r.get("controls", {})}
                for r in high
            ],
            "notes": [
                "Risk scoring model is a project-specific quantitative approximation.",
                "Inherent vs residual aligns with NIST SP 800-30 concepts (methodology), not a mandated formula.",
                "CIS safeguard IDs in this MVP are illustrative and should be validated for a formal thesis.",
            ],
        }

        safe_asset = sanitize_filename(asset["name"])
        filename = f"threat_report_{safe_asset}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"\nSaved report: {filename}")



# Main

def main():
    os.system("clear" if os.name == "posix" else "cls")
    banner()

    print("This CLI turns a strategic principle into measurable security decisions.")
    print("Curated ATT&CK subset + NIST-style risk concepts + CIS-aligned control mapping (illustrative).\n")

    input("Press Enter to start...")

    asset = module_asset_profile()
    actor_name, actor = module_threat_actor()
    coverage_results, tactic_stats, coverage_pct = module_coverage_matrix(actor)
    risk_items, tactic_risk = module_risk_scoring(asset, coverage_results)
    module_recommendations_and_report(risk_items, asset, actor_name, coverage_pct, tactic_stats, tactic_risk)

    print("\n" + "=" * 78)
    print("Analysis complete — ATT&CK-Driven Threat Model (MVP++)")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
