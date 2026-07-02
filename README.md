# Shift-left-firmware-pipeline

An Automated CI/CD pipeline that intercepts a firmware build on every push, extracts its filesystem, performs static analysis for hardcoded credentials, expired certificates, outdated binaries, and known CVEs and then uses AI-driven triage to auto-generate alerts and tracking tickets for high-severity risks.

## Problem Statement

Firmware is typically shipped as a compiled binary "black box" that standard application security scanners cannot inspect. Vulnerabilities like plaintext credentials, expired certs, and outdated components are usually caught only by late-stage manual audits, sometimes after the device has shipped - when fixes mean recalls or risky OTA updates. 

This project *shifts security left*: scanning happens automatically at commit time, and findings arrive as plain-English triage summaries instead of raw logs.

## Repository Structure

```
firmware/            Mock vulnerable firmware artifact (planted flaws documented in docs/)
scripts/             Extraction and scan helper scripts
.github/workflows/   CI pipeline definitions
docs/                Threat model, attack vectors, correlation matrix, report samples
```
