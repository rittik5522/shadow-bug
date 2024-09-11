# Shadow Bug - The Ultimate Bug Hunting Tool

Shadow Bug is an all-in-one tool for bug bounty hunters and penetration testers. It automates various tasks like subdomain enumeration, directory brute-forcing, SQL injection scanning, XSS testing, and more.

## Features

- **Subdomain Enumeration**: Find subdomains of a target website.
- **Directory Brute-Force**: Discover hidden directories on a website.
- **SQL Injection Scan**: Automate SQL Injection scanning with SQLmap.
- **XSS Test**: Check for Cross-Site Scripting vulnerabilities.
- **Port Scanning**: Scan for open ports using Nmap.
- **CMS Detection (WordPress)**: Detect WordPress vulnerabilities with WPScan.
- **SSL/TLS Vulnerability Scan**: Check SSL/TLS configurations for weaknesses.
- **DNS Zone Transfer Check**: Test if DNS zone transfer is enabled.

## Installation

### Prerequisites

Make sure you are running **Kali Linux** or **Parrot Security OS**, and you have Python 3 installed.

### Install Dependencies

Run the following commands to install all the required dependencies:

```bash
sudo apt update
sudo apt install sublist3r dirb sqlmap nmap wpscan sslyze python3-pip
pip3 install requests pyfiglet termcolor
git clone https://github.com/yourusername/ShadowBug.git
cd ShadowBug
chmod +x shadowbug.py
./shadowbug.py
