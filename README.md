# Network Port Scanner & Service Analyzer

A Python-based cybersecurity project that scans authorized systems for open network ports, identifies running services and versions, and provides basic security risk analysis through a Streamlit dashboard.

## Project Overview

The Network Port Scanner & Service Analyzer is designed to simplify basic network reconnaissance and security analysis.

The application uses Nmap to detect open ports and identify associated services and software versions. The scan results are then analyzed using predefined security rules and presented through an interactive Streamlit dashboard.

The project was developed for educational and cybersecurity lab purposes.

## Features

- Scan an authorized IP address or hostname
- Detect open network ports
- Identify running services
- Detect available product and version information
- Perform basic security risk analysis
- Classify detected services as LOW, MEDIUM, or HIGH risk
- Display security recommendations
- View scan history
- Export scan results in CSV format
- Export scan results in JSON format
- Interactive Streamlit dashboard
- Dashboard theme selection
- Multiple scan profiles

## Technologies Used

- Python
- Nmap
- python-nmap
- Streamlit
- Pandas
- JSON

## Project Architecture

The application follows this workflow:

Authorized Target
        ↓
Streamlit Dashboard
        ↓
Scan Configuration
        ↓
Nmap Scanner
        ↓
Open Port Detection
        ↓
Service & Version Detection
        ↓
Security Analysis
        ↓
Risk Classification
        ↓
Security Recommendations
        ↓
Dashboard & Scan History
        ↓
CSV / JSON Export

## Project Structure

```text
Network-Port-Scanner/
│
├── app.py
├── scanner.py
├── analyzer.py
├── history.py
├── validators.py
├── security.py
├── requirements.txt
├── scan_history.json
├── screenshots/
├── README.md
└── .gitignore
File Description

app.py
Main Streamlit dashboard and application interface.

scanner.py
Handles Nmap scanning and extracts port, service, product, and version information.

analyzer.py
Performs basic security analysis and assigns risk levels with recommendations.

history.py
Handles loading and saving scan history.

validators.py
Validates port and port-range input.

security.py
Provides security-status related functionality used by the dashboard.

requirements.txt
Contains the required Python dependencies.

scan_history.json
Stores local scan history.

Requirements
Software Requirements
Kali Linux or another Linux-based environment
Python 3
Nmap
pip / Python virtual environment
Python Dependencies
streamlit==1.63.0
pandas==3.0.5
python-nmap==0.7.1
Installation

Clone the repository:

git clone <REPOSITORY-URL>

Move into the project directory:

cd Network-Port-Scanner

Create a virtual environment:

python3 -m venv .venv

Activate the virtual environment:

source .venv/bin/activate

Install the required Python packages:

pip install -r requirements.txt

Make sure Nmap is installed:

nmap --version
Running the Application

Start the Streamlit dashboard:

streamlit run app.py

The application can then be accessed through the local Streamlit URL displayed in the terminal.

Example Scan

During development and testing, the project was tested using the local system:

127.0.0.1

Example detected service:

Port       : 22
State      : open
Service    : SSH
Product    : OpenSSH
Version    : 10.3p1 Debian 4
Risk Level : MEDIUM

The analyzer provides a security recommendation based on the detected service.

Scan Profiles

The dashboard supports different scan configurations, including:

Quick Scan
Standard Scan
Service Detection
Custom Scan

The custom scan option allows the user to specify ports or port ranges.

Security Analysis

The project uses predefined rules to provide basic risk classification.

Examples of analyzed services include:

FTP
Telnet
SSH
SMTP
HTTP
HTTPS
SMB
RDP
MySQL
PostgreSQL

The risk classification is intended for basic educational analysis and does not replace a professional vulnerability assessment.

Scan History

The application stores previous scan information locally in:

scan_history.json

The dashboard provides a dedicated Scan History section for reviewing previous scans.

Export

The application supports exporting scan results in:

CSV
JSON

These formats can be used for documentation, analysis, and reporting.

Screenshots

Project screenshots are available in the screenshots/ directory.

The screenshots demonstrate:

Main Dashboard
Port Security Analysis / Scan Results
Scan History
Security Notice

This project should only be used against systems for which you have explicit authorization to perform scanning.

Do not scan third-party systems, networks, or websites without permission.

The project was developed and tested primarily in an educational/lab environment.

Future Enhancements

Possible future improvements include:

CVE and vulnerability database integration
More detailed vulnerability detection
Advanced service fingerprinting
Automated report generation
Additional scan techniques
Improved result visualization
Database-based scan history
Authentication and user management
Project Purpose

This project demonstrates practical implementation of basic network reconnaissance, Nmap integration, service detection, security analysis, and dashboard development using Python.

Author

Harsh Vijay Bahadur Singh

PG Diploma in AI Enhanced Cyber Security
