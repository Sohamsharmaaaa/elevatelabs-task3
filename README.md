# Cyber Security Internship - Task 3: Vulnerability Scanning

This repository contains my work for Task 3 of the Cyber Security Internship, where I performed a basic vulnerability scan using Nessus Essentials.

## Task Overview
- **Objective**: Identify common vulnerabilities on my personal computer
- **Tool Used**: Nessus Essentials (free version)
- **Scan Target**: Localhost (192.168.1.6)
- **Scan Type**: Basic Network Scan
- **Duration**: 8 minutes

## Vulnerability Summary
| Severity  | Count |
|-----------|-------|
| Critical  | 0     |
| High      | 0     |
| Medium    | 27    |
| Low       | TBD   |
| Info      | TBD   |

## Notable Vulnerability: SMB Signing Not Required

### Details
- **Plugin ID**: 57608
- **Severity**: Medium
- **CVSS v3.0 Score**: 5.3
- **Family**: Misc.
- **Published**: January 19, 2012
- **Modified**: October 5, 2022

  # Nessus Essentials Vulnerability Scan Report

## Scan Details
- **Policy**: Basic Network Scan
- **Status**: Completed
- **Scanner**: Local Scanner
- **Start Time**: Today at 6:38 PM
- **Duration**: 8 minutes
- **Target**: 192.168.1.6 (localhost)
  
## Key Findings
- Total vulnerabilities found: 115
- Medium severity vulnerabilities: 27
- Most notable vulnerability: SMB Signing not required (Medium severity, CVSS 5.3)

## Screenshots
1. Scan summary showing 115 vulnerabilities found
   ![Screenshot 2025-07-03 185732](https://github.com/user-attachments/assets/1e7a1508-6164-412e-8523-dc73594f5276)

2. Host details showing the scanned IP address
   ![Screenshot 2025-07-03 185749](https://github.com/user-attachments/assets/4cf43cdb-4fb5-4e07-8c67-41c009800c83)

3. Vulnerability details for "SMB Signing not required"
   ![Screenshot 2025-07-03 222451](https://github.com/user-attachments/assets/c89b77e9-abcf-4c28-83e1-f9d462cdc2ef)


## Remediation Steps
For the most critical vulnerability found (SMB Signing not required):
1. **Windows**: Enable 'Microsoft network server: Digitally sign communications (always)' in Group Policy
2. **Samba**: Set 'server signing = mandatory' in smb.conf

## Concepts Learned
- Vulnerability scanning process
- CVSS scoring system (v3.0)
- Interpreting Nessus scan results
- Basic vulnerability remediation

### Description
Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.

