# Compliance

Index of regulations and procurement standards the product respects, and the data flows that depend on them. Required by `.cursor/rules/compliance-and-regulation.mdc`.

## Regulations And Standards Tracked

- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA)
- NIST FIPS 205 (SLH-DSA)
- HQC selection (March 2025) as backup KEM
- CISA PQC procurement advisory (January 2026)
- CNSA 2.0 deadline (January 2027 for new National Security System acquisitions)
- eIDAS 2.0 (EU digital identity)
- GDPR (EU 2016/679)
- NIS-2 (EU 2022/2555)
- ISO/IEC 27001 alignment
- SOC 2 readiness
- HIPAA when health data is in scope

## Data Flow Inventory

| Data Category | Lawful Basis | Location Of Processing | Retention Rule | Deletion Mechanism | Visible To Backend | Visible To Mobile |
|---------------|--------------|------------------------|----------------|--------------------|--------------------|-------------------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _ciphertext only?_ | _plaintext?_ |

## Subprocessors

| Name | Purpose | Region | DPA Status | Date Added |
|------|---------|--------|------------|------------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |

## Self-Hosting And On-Prem

- Document data residency per deployment.
- Document operator responsibilities (DB credentials, signing keys, replay store backing, log destination, key-rotation cadence).
- Self-hosting is a first-class deployment mode, not an afterthought.

## Logging And Telemetry

- Plaintext, key material, signatures past their useful lifetime, ZK witnesses, and recovery material are forbidden in logs, telemetry, and crash reports.
- Sampling rules and redaction policies live here.

## Pre-Release Checklist

| Release | Date | Reviewer | Findings | Status |
|---------|------|----------|----------|--------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |
