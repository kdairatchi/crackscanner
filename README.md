# crackscanner
Nmap on crack using py
Here is the complete project with all the necessary files and instructions on how to run it:

**How to Run:**
Virtual Environment (Optional but recommended): Create a virtual environment to manage dependencies and avoid conflicts with system-wide packages.

    Install Python 3.10 (or later) from the official Python website.

    python -m venv venv
    source venv/bin/activate  # On Windows use: venv\Scripts\activate



	Install Dependencies:

    pip install -r requirements.txt


    Ensure exploit_repository.py is in the same directory or correctly referenced.
    Run the Script:

    python port_scanner.py <host> <start_port> <end_port> [-v]
 
 =================##########################======================================================

1. Save the `exploit_repository.py`, `port_scanner.py`, and `main.py` files in the same directory.

2. Install the `requests` library by running `pip install requests` in your terminal.

3. Run the `main.py` file by typing `python main.py` in your terminal.

4. Enter your API key when prompted.

5. If the API key is valid, the script will print a list of exploits retrieved from the API.

6. You can then use the `port_scanner.py` file to scan a range of ports on a host and detect potential vulnerabilities.

7. To run the port scanner, type `python port_scanner.py <host> <start_port> <end_port>` in your terminal, replacing `<host>` with the IP address of the host you want to scan, and `<start_port>` and `<end_port>` with the range of ports you want to scan.

 

Example:

```

python port_scanner.py 192.168.1.1 1 1024

```

This will scan the host `192.168.1.1` from port 1 to port 1024 and display the results.

 

Note: Make sure to replace the `https://api.example.com/v1/check` and `https://api.example.com/v1/exploits` URLs in the `main.py` file with the actual URLs of the API you are using.


**File Structure:**

 

* `exploit_repository.py`

* `port_scanner.py`

* `main.py`

 

**exploit_repository.py:**

 

```python

# exploit_repository.py

 

# A dictionary of exploits associated with specific CVEs and ports

EXPLOIT_REPOSITORY = {

    21: {

        "CVE-2019-11043": {

            "description": "FTP: Anonymous login vulnerability",

            "exploit": "Use Metasploit module `auxiliary/scanner/ftp/anonymous`."

        }

    },

    22: {

        "CVE-2016-0777": {

            "description": "SSH: Potential weak ciphers",

            "exploit": "Consider disabling weak ciphers or using `ssh-audit`."

        }

    },

    23: {

        "description": "Telnet: Cleartext transmission of sensitive information",

        "exploit": "Use a secure alternative like SSH."

    },

    25: {

        "description": "SMTP: Open relay vulnerability",

        "exploit": "Check for open relay configuration."

    },

    80: {

        "CVE-2021-22963": {

            "description": "HTTP: Directory traversal vulnerability",

            "exploit": "Check for files outside the web root."

        }

    },

    443: {

        "CVE-2014-3566": {

            "description": "HTTPS: SSLv3 POODLE vulnerability",

            "exploit": "Disable SSLv3 on the server."

        }

    },

    3306: {

        "CVE-2012-2122": {

            "description": "MySQL: Remote root access vulnerability",

            "exploit": "Restrict remote root access."

        }

    },

    3389: {

        "CVE-2019-0708": {

            "description": "RDP: BlueKeep vulnerability",

            "exploit": "Use Metasploit module `exploit/windows/rdp/cve_2019_0708_bluekeep_rce`."

        }

    },

    5222: {

        "CVE-2020-12695": {

            "description": "XMPP (Jabber): Potential for remote code execution",

            "exploit": "Review XMPP server configurations."

        }

    },

    # Add more ports and vulnerabilities as needed

}

```

 

**port_scanner.py:**

 

```python

import socket

from concurrent.futures import ThreadPoolExecutor

import argparse

from exploit_repository import EXPLOIT_REPOSITORY  # Import the exploit repository

 

def prompt_for_db_connection():

    """Prompt the user for connecting to a vulnerability database."""

    choice = input("Do you want to connect to a vulnerability database (NVD/Exploit-DB)? (yes/no): ").strip().lower()

    if choice == 'yes':

        print("To connect to a vulnerability database, you may need to create an account.")

        print("1. **NVD**: Visit https://nvd.nist.gov/ to create an account.")

        print("2. **Exploit-DB**: Visit https://www.exploit-db.com/ to create an account.")

        print("\nAfter creating an account, you will need an API key or credentials to access the API.")

        api_key = input("Enter your API key (or leave blank if not using): ").strip()

        return api_key

    else:

        print("Continuing without a database connection.")

        return None

 

def scan_port(host, port, verbose):

    """Scan a single port on the host."""

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(1)  # Set timeout for socket connection

            result = sock.connect_ex((host, port))

            if result == 0:

                if verbose:

                    print(f"[+] Port {port} is open on {host}")

                return port

            else:

                if verbose:

                    print(f"[-] Port {port} is closed on {host}")

                return None

    except socket.error as e:

        if verbose:

            print(f"[!] Could not connect to {host}:{port} - {e}")

        return None

 

def detect_os(open_ports):

    """Detect OS based on open ports (basic heuristic)."""

    if 22 in open_ports:

        return "Linux (SSH)"

    elif 80 in open_ports or 443 in open_ports:

        return "Web Server (Linux/Windows)"

    elif 135 in open_ports:

        return "Windows (RPC)"

    elif 5222 in open_ports:

        return "Android (XMPP)"

    elif 5223 in open_ports:

        return "iOS (XMPP)"

    return "Unknown OS"

 

def check_vulnerabilities(open_ports):

    """Check for vulnerabilities based on open ports using the exploit repository."""

    vulnerabilities_found = {}

    for port in open_ports:

        if port in EXPLOIT_REPOSITORY:

            vulnerabilities_found[port] = EXPLOIT_REPOSITORY[port]

    return vulnerabilities_found

 

def scan_ports(host, start_port, end_port, verbose):

    """Scan a range of ports on the host."""

    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = {executor.submit(scan_port, host, port, verbose): port for port in range(start_port, end_port + 1)}

        for future in futures:

            result = future.result()

            if result is not None:

                open_ports.append(result)

 

    return open_ports

 

def display_results(open_ports, api_key=None):

    """Display the scan results and potential vulnerabilities."""

    if open_ports:

        os_detected = detect_os(open_ports)

        print(f"\n[+] Open ports: {open_ports}")

        print(f"[+] Detected OS: {os_detected}")

 

        vulnerabilities = check_vulnerabilities(open_ports)

        if vulnerabilities:

            print("[+] Potential vulnerabilities found:")

            for port, details in vulnerabilities.items():

                print(f"   Port {port}:")

                for cve, exploit in details.items():

                    print(f"     - {cve}: {exploit['description']}")

                    print(f"       Exploit: {exploit['exploit']}")

        else:

            print("[-] No known vulnerabilities found.")

    else:

        print("\n[-] No open ports found.")

 

def main_menu():

    """Display the main menu for user interaction."""

    print("\n[1] Rescan ports")

    print("[2] Save results to file")

    print("[3] Exit")

 

def save_results(open_ports, os_detected):

    """Save the scan results to a file."""

    with open("scan_results.txt", "w") as f:

        f.write(f"Open ports: {open_ports}\n")

        f.write(f"Detected OS: {os_detected}\n")

        print("[+] Results saved to scan_results.txt")

 

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Enhanced Port Scanner with Vulnerability Detection')

    parser.add_argument('host', help='Host to scan (e.g., 192.168.1.1)')

    parser.add_argument('start_port', type=int, help='Starting port number (e.g., 1)')

    parser.add_argument('end_port', type=int, help='Ending port number (e.g., 1024)')

    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

   

    args = parser.parse_args()

 

    # Prompt for database connection

    api_key = prompt_for_db_connection()

   

    print(f"Scanning {args.host} from port {args.start_port} to {args.end_port}...")

    open_ports = scan_ports(args.host, args.start_port, args.end_port, args.verbose)

   

    display_results(open_ports, api_key)

 

    if open_ports:

        os_detected = detect_os(open_ports)

       

        while True:

            main_menu()

            choice = input("Select an option: ")

           

            if choice == '1':

                print(f"Rescanning {args.host} from port {args.start_port} to {args.end_port}...")

                open_ports = scan_ports(args.host, args.start_port, args.end_port, args.verbose)

                display_results(open_ports, api_key)

            elif choice == '2':

                save_results(open_ports, os_detected)

            elif choice == '3':

                print("Exiting...")

                break

            else:

                print("Invalid option. Please try again.")

```

 

**main.py:**

 

```python

import requests

 

def check_api(api_key):

    url = "https://api.example.com/v1/check"

    headers = {"Authorization": f"Bearer {api_key}"}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:

        return True

    else:

        return False

 

def get_exploits(api_key):

    url = "https://api.example.com/v1/exploits"

    headers = {"Authorization": f"Bearer {api_key}"}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:

        return response.json()

    else:

        return []

 

def main():

    api_key = input("Enter your API key: ")

    if check_api(api_key):

        print("API key is valid")

        exploits = get_exploits(api_key)

        for exploit in exploits:

            print(exploit)

    else:

        print("API key is invalid")

 

if __name__ == "__main__":

    main()

```
