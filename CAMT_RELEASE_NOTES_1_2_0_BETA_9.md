# CAMT Professional Edition 1.2.0 Beta 10 - Release Notes

**Version:** 1.2.0 Beta 10  
**Build:** 120B10-LIC-20260929  
**Channel:** beta  
**Release sequence:** 8

## Release focus

Beta 10 further integrates CAMT's analyst-driven workflow from technical network evidence through threat-intelligence correlation and professional reporting.

## Network and assessment workflow

- Improved Network Mapper / NetMap workflow for larger environments.
- Improved large-map zooming, panning and level-of-detail behavior.
- Improved multi-monitor window handling and geometry restoration.
- Exercise Network Assessment supports guided analyst workflow.
- Assessment results include Network Overview, Crown Jewels, Choke Points, Single Points of Failure and Trust Boundaries.
- Assessment sessions can be saved and reopened.
- Baseline comparison supports analyst review of environmental changes.

## Threat intelligence and behavioral analysis

- External CTI can be used as structured evidence for CAMT analysis.
- Behavioral Similarity supports comparison of observed modus-operandi patterns with threat-actor profiles.
- Candidate assessment distinguishes supporting, contradictory and missing evidence.
- Similarity remains a hypothesis-support mechanism and must not be interpreted as automatic attribution.

## CTI Correlation Assessment

- Guided workflow: CTI Report -> Network Evidence -> Extract -> Correlate -> Review -> Report.
- Correlation compares external intelligence with observed environment evidence.
- Finding details provide source context, local evidence, correlation reasoning, evidence gaps and analyst guidance.
- Evidence-aware outcomes distinguish confirmed local evidence, probable relevance, contextual relevance, no supporting evidence, contradictory evidence and not-assessable findings.
- CVE findings require sufficient product/version evidence before applicability can be concluded.
- Analyst-facing workflow reduces the need to manually navigate between CAMT modules.

## Reporting

- Exercise Network Assessment can generate native CAMT report data.
- Report visuals are generated without a Cairo runtime dependency.
- Professional Report Studio supports CAMT report handoff.
- PDF, DOCX, HTML and TXT publication workflows are supported.
- Report content preserves the distinction between observed evidence, CAMT-derived assessment and analyst conclusions.

## Beta notice

CAMT 1.2.0 Beta 10 is pre-release software. Validate significant findings independently before operational use.

Build: 120B10-LIC-20260929
