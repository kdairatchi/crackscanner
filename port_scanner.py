import socket
from concurrent.futures import ThreadPoolExecutor
import argparse
from exploit_repository import EXPLOIT_REPOSITORY

def prompt_for_db_connection():
    choice = input("Do you want to connect to a vulnerability database (NVD/Exploit-DB)? (yes/no): ").strip().lower()
    if choice == 'yes':
        print("To connect to a vulnerability database, you may need to create an account.")
        print("1. **NVD**: Visit https://nvd.nist.gov/ to create an account.")
        print("2. **Exploit-DB**: Visit https://www.exploit-db.com/ to create an account.")
        api_key = input("Enter your API key (or leave blank if not using): ").strip()
        return api_key
    else:
        return None

def scan_port(host, port, verbose):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
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
    vulnerabilities_found = {}
    for port in open_ports:
        if port in EXPLOIT_REPOSITORY:
            vulnerabilities_found[port] = EXPLOIT_REPOSITORY[port]
    return vulnerabilities_found

def scan_ports(host, start_port, end_port, verbose):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port, verbose): port for port in range(start_port, end_port + 1)}
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return open_ports

def display_results(open_ports, api_key=None):
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
    print("\n[1] Rescan ports")
    print("[2] Save results to file")
    print("[3] Exit")

def save_results(open_ports, os_detected):
    with open("scan_results.txt", "w") as f:
        f.write(f"Open ports: {open_ports}\n")
        f.write(f"Detected OS: {os_detected}\n")
        print("[+] Results saved to scan_results.txt")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("Usage: port_scanner.py <host> <start_port> <end_port> [-v]")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Enhanced Port Scanner with Vulnerability Detection')
    parser.add_argument('host', help='Host to scan (e.g., 192.168.1.1)')
    parser.add_argument('start_port', type=int, help='Starting port number (e.g., 1)')
    parser.add_argument('end_port', type=int, help='Ending port number (e.g., 1024)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

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
                open_ports = scan_ports(args.host, args.start_port, args.end_port, args.verbose)
                display_results(open_ports, api_key)
            elif choice == '2':
                save_results(open_ports, os_detected)
            elif choice == '3':
                print("Exiting...")
                break
            else:
                print("Invalid option. Please try again.")
