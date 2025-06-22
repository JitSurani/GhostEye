#!/usr/bin/env python3

import subprocess
import os
import time
import requests
import whois
import ipaddress
import hashlib
import json
from ipwhois import IPWhois

def print_banner():
    os.system("clear")
    print(r"""
     ________.__                    __    ___________             
 /  _____/|  |__   ____  _______/  |_  \_   _____/__.__. ____  
/   \  ___|  |  \ /  _ \/  ___/\   __\  |    __)<   |  |/ __ \ 
\    \_\  \   Y  (  <_> )___ \  |  |    |        \___  \  ___/ 
 \______  /___|  /\____/____  > |__|   /_______  / ____|\___  >
        \/     \/           \/                 \/\/         \/ 

          || -- OSINT Reconnaissance Framework-- ||
                        Made by Js
    """)

def menu():
    print("Select an option:")
    print("1. Dorking -- (Social-Media)")
    print("2. Site Details && DNS Dumping")
    print("3. Search via Name/Number")
    print("4. DNS Footprinting")
    print("5. Network Footprinting")
    print("6. Email Footprinting")
    print("7. OSINT Tool --- RECON-NG")
    print("8. Exit")

def google_dorking():
    print("\n[+] Dorking using DDGR")
    print("You will only get the Names, then you have to go to individual sites for searching, as Social Networking sites block these bots.")
    print("INFO: Press Enter 3 times after getting Info, for returning to the Main Menu")
    dork = input("\nEnter your dork/query: ")
    print("\nWARNING: More number of queries will lead to irrelevant result.")
    numb = input("\nEnter the Number of query to search: ")
    subprocess.run(["ddgr", "-n", numb, dork])

def netcraft_dnsdumpster():
    print("\n[+] Netcraft Site Report")
    print("Writing Method ::-- example.com --::")
    domain = input("Enter domain: ")
    url = f"https://sitereport.netcraft.com/?url={domain}"
    print("RESULT FOR NETCRAFT --| (You will be directed to Netcraft site for the detailed informational)")
    print(f"Open the URL in browser:\n{url}\n")

    print("\n[+] RESULT FOR DNSDumpster")
    from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
    try:
        subprocess.run(["dnsrecon", "-d", domain])
    except:
        print("[-] Failed to fetch DNSDumpster data. Install dnsdumpster module if needed.")

def maigret_search():
    print("\n[+] Deep Search")
    print("The Link will be provieded and will be used only if you have already logged in that particular site.")
    print("WARNING: Field is CASE SENSITIVE, Search Accordingly")
    username = input("Enter username to search: ")
    print("\nWARNING: More number of queries will lead to irrelevant result.")
    site_numb = input("Enter the number of query to search:  ")
    subprocess.run(["maigret", username, "--top-sites", site_numb, "--timeout", "15", "--retries", "2"])

def dns_footprinting():
    domain = input("\nEnter domain for DNS Footprinting: ")
    print("\n[+] Record 1 --- data::")
    subprocess.run(["nslookup", domain])
    print("\n[+] Record 2 --- data::")
    subprocess.run(["dig", domain, "MX", "+short"])

def traceroute_trace():
    host = input("\nEnter domain/IP: ")
    num_hop = input("\nEnter the Maximum number of hops: ")
    subprocess.run(["traceroute", "-m", num_hop, host])

def run_recon_ng():
    print("\n[+] Launching recon-ng CLI...")
    subprocess.run(["recon-ng"])

def email_footprinting():
    target = input("\nEnter email or domain: ").strip()

    if '@' in target:
        domain = target.split('@')[-1]
        email = target
    else:
        domain = target
        email = None

    print("\n[+] MX Records (using dig):")
    try:
        subprocess.run(["dig", domain, "MX", "+short"], check=True)
    except Exception:
        print("[-] 'dig' command not found or failed. Install with: sudo apt install dnsutils")

    print("\n[+] MXToolBox URL:")
    print(f"https://mxtoolbox.com/SuperTool.aspx?action=mx:{domain}")

    if email:
        print("\n[+] Gravatar Profile Check:")
        hash_email = hashlib.md5(email.strip().lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{hash_email}?d=404"
        try:
            response = requests.get(gravatar_url)
            if response.status_code == 200:
                print(f"[✓] Gravatar Found: {gravatar_url}")
            else:
                print("[-] No Gravatar profile found.")
        except Exception as e:
            print(f"[-] Gravatar check failed: {e}")

        print("\n[+] Breach Check via HaveIBeenPwned (Public Check):")
        try:
            headers = {"User-Agent": "GhostEyeOSINT"}
            res = requests.get(f"https://haveibeenpwned.com/unifiedsearch/{email}", headers=headers)
            if res.status_code == 200 and "Domain" in res.text:
                print("[✓] Found in data breaches!")
            elif res.status_code == 404:
                print("[-] Not found in any known breaches.")
            else:
                print("[-] HIBP query failed or blocked.")
        except Exception as e:
            print(f"[-] HIBP check failed: {e}")

        print("\n[+] Hunter.io Email Verifier (Manual):")
        print(f"https://hunter.io/email-verifier/{email}")

        print("\n[+] Epieos Email Lookup (Manual):")
        print(f"https://tools.epieos.com/email.php?email={email}")

def main():
    print_banner()

    while True:
        menu()
        choice = input("\nEnter your choice [1-8]: ")

        if choice == '1':
            google_dorking()
        elif choice == '2':
            netcraft_dnsdumpster()
        elif choice == '3':
            maigret_search()
        elif choice == '4':
            dns_footprinting()
        elif choice == '5':
            traceroute_trace()
        elif choice == '7':
            run_recon_ng()
        elif choice == '6':
            email_footprinting()
        elif choice == '8':
            print("\n[+] Exiting GhostEye. Stay anonymous 👻\n")
            print("Made By : Js")
            time.sleep(3)
            break
        else:
            print("Invalid choice. Try again.")
        input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
    main()
