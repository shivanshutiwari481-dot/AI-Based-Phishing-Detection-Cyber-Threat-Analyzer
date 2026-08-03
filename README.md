# Aegis Cyber AI - Phishing Detection & Threat Analysis System
[![GitHub Developer](https://img.shields.io/badge/GitHub-shivanshutiwari481-00f3ff?logo=github&style=flat-square)](https://github.com/shivanshutiwari481)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff88.svg?style=flat-square)](LICENSE)
[![Built with React](https://img.shields.io/badge/Frontend-React%20%7C%20TypeScript%20%7C%20Tailwind-indigo?style=flat-square)](https://react.dev)
A state-of-the-art **AI-Based Phishing Detection & Cyber Threat Intelligence System** designed for SOC analysts, incident response teams, and security researchers.
Developed by **[shivanshutiwari481](https://github.com/shivanshutiwari481)**.
---
## 🌟 Key Features
1. **Multi-Vector Threat Analyzers**:
   - **URL Phishing Inspector**: Analyzes Shannon entropy, homoglyph typosquatting (e.g. `g00gle.com`, `paypal-security-update.top`), raw IP hostnames, high-risk TLDs (`.top`, `.xyz`), SSL encryption status, and brand impersonation indices.
   - **Email Header & NLP Inspector**: Checks SPF, DKIM, and DMARC alignment, spoofed sender domains (`From` vs `Return-Path`), and body text NLP intent (urgency keywords, wire transfer triggers, credential harvesting).
   - **Static File Payload & YARA Inspector**: Computes Shannon binary entropy, SHA-256 / MD5 cryptographic hashes, and evaluates dynamic YARA signatures for obfuscated PowerShell downloaders and process injection APIs.
2. **Explainable AI (XAI) Engine**:
   - Visual breakdown of neural feature weights explaining *why* a specific risk score (0 to 100) was assigned.
   - Interactive bar charts and detailed parameter impact lists.
3. **Cyber Threat Intelligence (CTI) Hub & Radar**:
   - Global Threat Radar animation tracking live simulated attack vectors.
   - Real-Time Incident Stream mapping incoming IOC triggers.
4. **MITRE ATT&CK® Enterprise Matrix Mapping**:
   - Maps detected threats directly to official TTPs (e.g. `T1566.002 Spearphishing Link`, `T1583.001 Acquire Domains`, `T1059.001 PowerShell`).
5. **Security Operations & SOAR Toolset**:
   - **Batch IOC Bulk Scanner**: Upload list of IPs, URLs, or file hashes with CSV report export.
   - **Typosquatting Generator**: Generate potential lookalike brand domains for DNS blocking.
   - **Forensic Incident Audit Report**: Instant Markdown audit report generation for SOC documentation.
---
## 🚀 Quick Start & Installation
### Prerequisites
- Node.js (v18 or higher)
- npm or yarn
### 1. Install Dependencies
```bash
npm install
```
### 2. Launch Local Dev Server
```bash
npm run dev
```
Open your browser at `http://localhost:5173`.
---
## 🐙 Push to GitHub Direct (`shivanshutiwari481`)
To push this codebase directly to your GitHub account:
```bash
git init
git add .
git commit -m "feat: initial commit for AI-Based Phishing Detection & Cyber Threat Analysis System by shivanshutiwari481"
git branch -M main
git remote add origin https://github.com/shivanshutiwari481/AI-Based-Phishing-Detection-Cyber-Threat-Analyzer.git
git push -u origin main
```
---
## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more details.
**Developer & Maintainer:** [shivanshutiwari481](https://github.com/shivanshutiwari481)

To push this codebase directly to your GitHub account:
```bash
git init
git add .
git commit -m "feat: initial commit for AI-Based Phishing Detection & Cyber Threat Analysis System by shivanshutiwari481"
git branch -M main
git remote add origin https://github.com/shivanshutiwari481/AI-Based-Phishing-Detection-Cyber-Threat-Analyzer.git
git push -u origin main
```
---
## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more details.
**Developer & Maintainer:** [shivanshutiwari481](https://github.com/shivanshutiwari481)
