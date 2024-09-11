#!/usr/bin/env python3

import os
import requests
import pyfiglet
from termcolor import colored

# Display banner with Shadow Bug name in color
def banner():
    ascii_banner = pyfiglet.figlet_format("Shadow Bug")
    colored_banner = colored(ascii_banner, 'cyan')
    print(colored_banner)
    print(colored("The Ultimate Bug Hunting Tool\n", 'yellow'))

# Subdomain Enumeration using Sublist3r
def subdomain_enum(domain):
    print(colored(f"\n[+] Starting Subdomain Enumeration for {domain}...", 'green'))
    os.system(f"sublist3r -d {domain} -o {domain}_subdomains.txt")
    print(colored(f"\n[+] Subdomain enumeration complete. Results saved in {domain}_subdomains.txt", 'blue'))

# Directory Bruteforce using Dirb
def dir_bruteforce(domain):
    print(colored(f"\n[+] Starting Directory Brute Force on {domain}...", 'green'))
    os.system(f"dirb http://{domain}")
    print(colored("\n[+] Directory brute force complete.", 'blue'))

# SQL Injection Scan using SQLmap
def sql_injection_scan(url):
    print(colored(f"\n[+] Starting SQL Injection Scan on {url}...", 'green'))
    os.system(f"sqlmap -u {url} --batch --crawl=3")
    print(colored("\n[+] SQL Injection scan complete.", 'blue'))

# XSS Testing with payload injection
def xss_test(url):
    print(colored(f"\n[+] Starting XSS Test on {url}...", 'green'))
    payload = "<script>alert('XSS')</script>"
    r = requests.get(url, params={'q': payload})
    if payload in r.text:
        print(colored("[+] XSS Vulnerability Detected!", 'red'))
    else:
        print(colored("[-] No XSS Vulnerability Detected.", 'blue'))

# Open Port Scanning using Nmap
def port_scan(domain):
    print(colored(f"\n[+] Starting Open Port Scanning for {domain}...", 'green'))
    os.system(f"nmap -sS -Pn {domain} -oN {domain}_nmap_scan.txt")
    print(colored(f"\n[+] Open Port Scan Complete. Results saved in {domain}_nmap_scan.txt", 'blue'))

# CMS Detection (WordPress vulnerability scan) using WPScan
def cms_scan(domain):
    print(colored(f"\n[+] Starting CMS (WordPress) Vulnerability Scan on {domain}...", 'green'))
    os.system(f"wpscan --url {domain} --enumerate vp --api-token YOUR_WPSCAN_API_KEY")
    print(colored(f"\n[+] CMS Scan Complete.", 'blue'))

# SSL/TLS Vulnerability Scan using SSLyze
def ssl_scan(domain):
    print(colored(f"\n[+] Starting SSL/TLS Vulnerability Scan for {domain}...", 'green'))
    os.system(f"sslyze --regular {domain}")
    print(colored("\n[+] SSL/TLS Scan Complete.", 'blue'))

# DNS Zone Transfer Check
def dns_check(domain):
    print(colored(f"\n[+] Checking DNS Zone Transfer for {domain}...", 'green'))
    os.system(f"dig axfr {domain}")
    print(colored("\n[+] DNS Zone Transfer Check Complete.", 'blue'))

# Main Menu
def main():
    banner()
    print(colored("1. Subdomain Enumeration", 'green'))
    print(colored("2. Directory Brute-Force", 'green'))
    print(colored("3. SQL Injection Scan", 'green'))
    print(colored("4. XSS Test", 'green'))
    print(colored("5. Open Port Scanning", 'green'))
    print(colored("6. CMS Detection (WordPress)", 'green'))
    print(colored("7. SSL/TLS Vulnerability Scan", 'green'))
    print(colored("8. DNS Zone Transfer Check", 'green'))

    choice = input("\nEnter your choice: ")

    if choice == '1':
        domain = input("Enter the domain: ")
        subdomain_enum(domain)
    elif choice == '2':
        domain = input("Enter the domain: ")
        dir_bruteforce(domain)
    elif choice == '3':
        url = input("Enter the URL: ")
        sql_injection_scan(url)
    elif choice == '4':
        url = input("Enter the URL: ")
        xss_test(url)
    elif choice == '5':
        domain = input("Enter the domain: ")
        port_scan(domain)
    elif choice == '6':
        domain = input("Enter the domain: ")
        cms_scan(domain)
    elif choice == '7':
        domain = input("Enter the domain: ")
        ssl_scan(domain)
    elif choice == '8':
        domain = input("Enter the domain: ")
        dns_check(domain)
    else:
        print(colored("Invalid choice. Please try again.", 'red'))

if __name__ == "__main__":
    main()
