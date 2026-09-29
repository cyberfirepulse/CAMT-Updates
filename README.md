# CAMT Professional Edition

## Cyber Advanced Threat Modeling Tool

CAMT Professional Edition is a modular cybersecurity analysis, threat-modeling, cyber threat intelligence, network analysis and digital forensics platform for IT, OT/ICS and hybrid environments.

CAMT brings technical observations, network evidence, cyber threat intelligence, forensic evidence and analyst assessment together in a structured workflow.

**Version:** 1.2.0 Beta 10
**Build:** 120B10-LIC-20260929
**Channel:** Beta
**Release:** v1.2.0-beta10

---

## Platform Support

CAMT Professional Edition Beta 10 supports:

* Microsoft Windows
* Linux
* IT environments
* OT/ICS environments
* Hybrid IT/OT environments

### Windows

Windows deployment is available as:

* `CAMT_Professional_Edition_1.2.0_Beta10_Setup_core.exe`
* `CAMT_Professional_Edition_1.2.0_Beta10_Setup.exe`

### Linux

CAMT Beta 10 includes a dedicated Linux installer with:

* Automatic Linux package-manager detection
* APT support
* DNF support
* YUM support
* Pacman support
* Zypper support
* Python 3.12+ runtime validation
* Isolated CAMT Python virtual environment
* Automatic runtime dependency installation
* Tkinter validation
* Scapy validation
* Cryptography runtime validation
* Python dependency consistency checks
* CAMT source compile validation
* Launcher validation

The Linux installer does not require manual installation of individual Python dependencies.

---

## Core Capabilities

### Network Discovery and Analysis

CAMT provides network discovery and infrastructure analysis capabilities for both local and routed environments.

Capabilities include:

* Network discovery
* Interface detection
* Subnet and route detection
* Nmap preflight validation
* Host and service discovery
* Device classification
* Network topology generation
* Interactive topology analysis
* Asset and infrastructure visualization
* IT and OT/ICS network analysis

NetMap supports:

* Local Interface
* VPN / Routed Network
* Jump Host / SSH

---

## Guided Network Analysis

Guided Network Analysis provides a structured workflow on top of the existing CAMT network-analysis capabilities.

The workflow is:

**Select Network -> Preflight -> Basic Scan -> Review -> Analyse in CAMT -> Report**

The guided workflow can summarize:

* Discovered hosts
* Network devices
* Servers
* Endpoints
* Detected services
* Assets requiring further review

Results can be continued through CAMT for deeper analysis, evidence handling, topology analysis and reporting.

---

## Network Modeling

CAMT can model infrastructure beyond a simple host list.

Analysis includes:

* Assets
* Services
* Network zones
* Relationships
* Dependencies
* Trust relationships
* Trust Boundaries
* Crown Jewels
* Choke Points
* Single Points of Failure
* Infrastructure relationships

This allows technical observations to be placed into an infrastructure and security context.

---

## Cyber Threat Intelligence

CAMT includes integrated Cyber Threat Intelligence capabilities for structured threat research and analysis.

### CTI Center

The CTI Center includes:

* Threat Knowledge Graph
* Relationship Explorer
* Actor Compare
* Similar Actors
* Trend Watch
* Structured actor information
* Relationship analysis
* JSON export
* HTML export

---

## Behavioral Match Engine

The Behavioral Match Engine supports comparison of observed behavior and available evidence against known threat-actor behavior.

Capabilities include:

* Behavioral similarity analysis
* Threat actor comparison
* Candidate assessment
* Evidence resolution
* Actor deduplication
* Analysis summaries
* Supporting evidence
* Contradictory evidence
* Missing evidence
* Insufficient-evidence handling

A behavioral similarity does not constitute attribution.

CAMT keeps candidate identification and evidential conclusions separate.

---

## Evidence-Aware Analysis

CAMT separates:

**Observation -> Correlation -> Assessment -> Conclusion**

A discovered host, service or open port is treated as an observation.

A technical or CTI correlation is treated as a correlation.

A vulnerability or actor relationship remains a candidate until sufficient supporting evidence is available.

CAMT is designed to make the following visible:

* Supporting evidence
* Contradictory evidence
* Missing evidence
* Confidence limitations
* Analyst reasoning
* Evidence gaps

This helps prevent correlation from being presented automatically as confirmed compromise, vulnerability or attribution.

---

## Digital Forensics and Evidence

CAMT contains forensic and evidence-oriented capabilities for working with collected data.

### Image Forensics

Image Forensics provides functionality for:

* Image preview
* Metadata inspection
* Forensic inspection
* Image analysis
* Evidence handling
* Camera-related metadata
* GPS information
* Evidence selection
* Controlled recovery workflows

### Data Carrier Forensics

Data Carrier Forensics supports analysis of storage media and recoverable data.

Capabilities include:

* Physical media analysis
* File-system inspection
* File discovery
* Recoverability assessment
* Preview
* Evidence classification
* Controlled recovery
* Progress indication
* File-system tree inspection

Recovery operations require explicit user action. CAMT does not automatically copy recovered data during analysis.

---

## Security Analysis

CAMT supports security analysis across discovered infrastructure and collected evidence.

Analysis can include:

* Asset assessment
* Service analysis
* Network exposure
* Security relationships
* Infrastructure dependencies
* Crown Jewel analysis
* Choke Point analysis
* Single Point of Failure analysis
* Trust Boundary analysis
* Threat correlation
* CTI correlation
* Evidence-based analyst assessment

---

## Reporting and Presentation

CAMT integrates analysis and evidence with reporting functionality.

Report Studio can be used to turn investigation results into structured professional output.

CAMT workflows can pass findings and evidence into reporting for:

* Investigation reports
* Technical findings
* Evidence summaries
* Network-analysis results
* CTI findings
* Analyst assessments
* Supporting visual material

---

## Modular Architecture

CAMT uses a modular architecture.

The Module Framework supports:

* CAMT modules
* Dynamic module discovery
* Module registration
* Module availability detection
* Version-aware modules
* Independently distributed functionality

This allows CAMT functionality to be extended without converting the complete application into a single monolithic component.

---

## Update Manager

The CAMT Update Manager supports controlled application and module updates.

Capabilities include:

* Package repository support
* Dynamic module discovery
* Available update detection
* Installed-version detection
* SHA-256 validation
* Package-ID validation
* Version validation
* Missing-module detection

Update states distinguish between:

* Available
* Update available
* Up to date

---

## License Management

CAMT contains an integrated licensing architecture supporting different operational environments.

Supported operating modes include:

* Online Private
* Offline
* Air-Gap-Strict

The licensing architecture supports:

* Signed license files
* Ed25519 signature validation
* License identification
* Installation/client identification
* Activation tracking
* Activation timestamps
* Last-validation tracking
* Activation counts
* License status tracking

License lifecycle states include:

**Issued -> Activated -> Active -> Expired / Revoked**

---

## Analytical Principle

CAMT is built around a simple principle:

**Observation is not automatically evidence.
Correlation is not automatically attribution.
Similarity is not automatically proof.**

CAMT supports the analyst by keeping evidence, reasoning, uncertainty and evidence gaps visible throughout an investigation.

---

## Typical Analysis Workflow

**Collect -> Normalize -> Correlate -> Assess -> Explain -> Report**

Depending on the investigation, this can combine:

* Network discovery
* Infrastructure modeling
* Security analysis
* Cyber Threat Intelligence
* Behavioral analysis
* Digital forensics
* Evidence assessment
* Reporting

---

## Linux Installation

Clone the CAMT repository:

```bash
git clone https://github.com/cyberfirepulse/CAMT-Updates.git
cd CAMT-Updates
```

Run the Linux installer:

```bash
sudo bash packaging/linux/install.sh
```

After a successful installation, start CAMT with:

```bash
camt
```

The installer performs dependency installation and runtime validation automatically.

---

## Windows Installation

Download the required Beta 10 installer.

### Core

`CAMT_Professional_Edition_1.2.0_Beta10_Setup_core.exe`

### Complete

`CAMT_Professional_Edition_1.2.0_Beta10_Setup.exe`

Verify the published SHA-256 checksum before installation.

---

## Documentation

See `QuickStart.pdf` for the operational introduction.

See `README_BETA.md` for Beta-specific information.

See the **Beta 10 release notes** for changes included in this release.

---

## Beta Software

CAMT Professional Edition 1.2.0 Beta 10 is a Beta release.

Beta releases are intended for testing, evaluation and controlled operational use. Findings from Beta testing can be used to improve stability, compatibility and functionality before a production release.

---

**CAMT Professional Edition**
**Version 1.2.0 Beta 10**
**Build 120B10-LIC-20260929**
