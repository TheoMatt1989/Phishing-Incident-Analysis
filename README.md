Overview

This repository contains a technical analysis of a phishing email incident, documented in a SOC-style report. The purpose of this project is to demonstrate skills in email threat detection, incident response, and security analysis. The analysis includes email identification, indicators of compromise (IOCs), containment actions, and recommendations for mitigating phishing threats.

Purpose

The goal of this project is to:

Identify and document phishing indicators in an email sample.

Perform a structured analysis using SOC best practices.

Demonstrate short-term containment and mitigation actions.

Highlight potential risks and impacts associated with phishing attacks.

Key Findings

The phishing email contained multiple red flags, including:

Poor grammar and linguistic anomalies.

Suspicious sender attributes (spoofed email).

Deceptive fine print and false urgency designed to manipulate recipients.

Indicators of compromise (IOCs) were identified, including malicious domain and IP address.

No user interaction occurred, and no system compromise was observed.

Containment Actions

Blocked the malicious domain at the email gateway.

Blocked the source IP address at the firewall.

Monitored for additional activity; no further incidents were detected.

Impact Assessment

Risk Level: Moderate

Potential impacts if interacted with included:

Credential theft and unauthorized access.

Malware infection or ransomware deployment.

Data exfiltration or lateral movement within the network.

Timely identification and containment minimized exposure.

Recommendations

Maintain phishing awareness and user training programs.

Enforce SPF, DKIM, and DMARC policies to improve email security.

Conduct periodic simulated phishing campaigns to assess response readiness.

Monitor for similar threat patterns and IOCs in the environment.

Repository Contents

phishing_report.pdf – Full SOC-style phishing report.

ioc_list.csv – Table of indicators of compromise (domains, IPs, and email addresses).

screenshots/ – Redacted screenshots of the phishing email and associated artifacts.

Usage

This repository is intended for educational purposes, demonstrating phishing detection, analysis, and reporting methodology. It can serve as a reference for SOC analysts, cybersecurity students, and security professionals looking to understand phishing investigations.# Phishing-Incident-Analysis
