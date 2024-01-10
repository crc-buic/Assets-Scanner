import os
import sys
import nmap
import json
from concurrent.futures import ThreadPoolExecutor

def discover_assets(ip_cidr):
    """
    Discover assets on the network using Nmap.
    :param ip_cidr: IP range in CIDR notation
    :return: List of IP addresses
    """
    nm = nmap.PortScanner()
    nm.scan(ip_cidr, arguments='-sn')

    ip_list = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    return ip_list

def detect_os(ip_list):
    """
    Perform OS detection for the IP addresses in the given list.
    :param ip_list: List of IP addresses
    :return: List of dictionaries containing scan results
    """
    scan_results = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(detect, ip) for ip in ip_list]

        for i, future in enumerate(futures, start=1):
            ip = ip_list[i-1]
            mac, detected_os = future.result()
            print(f'{i}: IP: {ip} | Mac: {mac} | OS: {detected_os}')
            scan_results.append({"IP": ip, "MAC": mac, "OS": detected_os})

    return scan_results

def detect(target):
    """
    Perform OS detection for a given IP address using Nmap.
    :param target: IP address to detect the operating system
    :return: Tuple containing the MAC address and detected operating system
    """
    try: 
        nm = nmap.PortScanner()
        machine = nm.scan(target, arguments='-v -sSU -pT:20-25,80,443-445,U:54321-54330 -O')

        addresses = machine['scan'][target]['addresses']
        host_mac = addresses.get('mac', 'Unknown')

        os_matches = machine['scan'][target].get('osmatch', [])
        best_match = max(os_matches, key=lambda x: x['accuracy']) if os_matches else None
        operating_system = best_match['name'] if best_match else 'Unknown'

        return host_mac, operating_system

    except Exception as e:
        print(e)
        return 'Unknown', 'Unknown'

def main(ip_cidr):
    """
    Entry point of the script.
    :param ip_cidr: IP range to scan in CIDR notation
    """
    
    if os.geteuid() != 0:
        print('You need to be root to run this script', file=sys.stderr)
        sys.exit(1)
    ip_list = discover_assets(ip_cidr)

    print(f'{len(ip_list)} hosts detected.\nDetecting OS .... \n')

    scan_results = detect_os(ip_list)

    with open("assets.json", "w") as write_file:
        json.dump(scan_results, write_file)

def usage():
    exit("Usage: %s -n <CIDR: IP Range>" % sys.argv[0])

if __name__ == "__main__":
    try:
        network = sys.argv[2]
        main(network)
    except Exception as e:
        print(e)
        usage()
