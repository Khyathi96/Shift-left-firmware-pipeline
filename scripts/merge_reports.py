#!/usr/bin/env python3
"""Merge Firmwalker, Trivy, and opkg_cve_check outputs into one unified report."""
import json, os, re, sys
from datetime import datetime, timezone

# Maps our finding 'type' -> Hardware rule ID
TYPE_TO_HW_RULE = {
    "hardcoded_credential": "HW-RULE-001",   # SPI flash dump of plaintext creds
    "private_key":          "HW-RULE-001",
    "exposed_service":      "HW-RULE-002",   # UART console / terminal daemons
    "outdated_package":     "HW-RULE-005",   # NEW: CVE / outdated library rule
    # HW-RULE-003 (JTAG) and HW-RULE-004 (unsigned firmware) have no detector yet
}

fw_txt, trivy_json, opkg_json, hw_rules_path, out_path = sys.argv[1:6]
hw_rules = {}
if os.path.exists(hw_rules_path):
    for rule in json.load(open(hw_rules_path)).get("hardware_context_rules", []):
        hw_rules[rule["id"]] = rule
findings = []

def add(source, ftype, severity, file, identifier, description):
    rule_id = TYPE_TO_HW_RULE.get(ftype)
    rule = hw_rules.get(rule_id) if rule_id else None
    hardware_context = None
    if rule:
        hardware_context = {
            "rule_id": rule["id"],
            "attack_surface": rule["attack_surface"],
            "access_required": rule["access_level_required"],
            "physical_vector": rule["simulated_exposure_vector"],
            "hw_severity": rule["default_severity"],
        }
    findings.append({
        "id": f"F-{len(findings)+1:03d}", "source": source, "type": ftype,
        "severity": severity, "file": file, "identifier": identifier,
        "description": description, "redacted": True,
        "hardware_context": hardware_context})

# --- Firmwalker: text output; paths listed under pattern headings ---
SEVERITY = {"password": ("hardcoded_credential", "HIGH"),
            "token":    ("hardcoded_credential", "HIGH"),
            "admin":    ("hardcoded_credential", "MEDIUM"),
            "private key": ("private_key", "HIGH"),
            "dropbear": ("exposed_service", "INFO")}
category = None
seen = set()
for line in open(fw_txt, errors="ignore"):
    line = line.strip()
    m = re.match(r"^-+ (.+?) -+$", line) or re.match(r"^#+ (.+)$", line)
    if m:
        category = m.group(1).strip()
        continue
    if line and category in SEVERITY and not line.startswith(("*", "#")):
        path = line.lstrip("t/")           # firmwalker's truncated-path quirk
        key = (category, path)
        if key not in seen:                # same file under same pattern once
            seen.add(key)
            ftype, sev = SEVERITY[category]
            add("firmwalker", ftype, sev, path, category,
                f"Pattern '{category}' matched in {path}")

# --- Trivy: JSON; secrets live under Results[].Secrets[] ---
trivy = json.load(open(trivy_json))
for result in trivy.get("Results") or []:
    for s in result.get("Secrets") or []:
        add("trivy", "private_key" if s["RuleID"] == "private-key" else "secret",
            s.get("Severity", "MEDIUM"), result.get("Target", ""),
            s.get("RuleID", ""), s.get("Title", ""))
    for v in result.get("Vulnerabilities") or []:   # empty today; future-proof
        add("trivy", "outdated_package", v.get("Severity", "MEDIUM"),
            v.get("PkgName", ""), v.get("VulnerabilityID", ""), v.get("Title", ""))

# --- opkg_cve_check: JSON; flat findings array ---
opkg = json.load(open(opkg_json))
for f in opkg.get("findings", []):
    add("opkg_cve_check", "outdated_package", f["severity"],
        f"{f['package']} {f['installed']} (fixed in {f['fixed_in']})",
        f["cve"], f["description"])

report = {
    "project": "shift-left-firmware-pipeline",
    "commit": os.environ.get("GITHUB_SHA", "local"),
    "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "firmware": os.environ.get("FIRMWARE_PATH", ""),
    "summary": {"total": len(findings),
                **{lvl.lower(): sum(1 for f in findings if f["severity"] == lvl)
                   for lvl in ("HIGH", "MEDIUM", "INFO")}},
    "findings": findings}

json.dump(report, open(out_path, "w"), indent=2)
print(f"[+] Unified report: {report['summary']}")
