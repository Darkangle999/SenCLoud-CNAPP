# Changelog

All notable changes to Odineyes are documented here.

## [2.1.0] - 2026-06-19

### Added
- Compliance framework catalogs: CIS AWS v1.5.0, SOC 2, HIPAA, GDPR,
  ISO 27001:2022, NIST 800-53, PCI DSS — wired into the compliance mapper
  and Statement of Applicability (SoA) export.
- Config / policy customization layer: per-deployment framework toggles,
  severity overrides, and custom policies (`config_store`, `policy_engine`,
  `config_routes` API, Settings UI page).
- Framework import from XLSX and XLSX compliance report export.

### Changed
- Grounded database risk scoring in security-group rules.

### Removed
- Kubernetes scanner and red-team lab scripts/manifests (AWS-only focus).

[2.1.0]: https://github.com/G3ntl3m3n-aka-praveen/Odineyes-CSPM/releases/tag/v2.1.0
