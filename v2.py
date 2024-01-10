import os
import sys
import nmap
import json

def scan(ip_cidr, list_name):
    """
    Perform network scanning using Zmap tool.
    :param ip_cidr: IP range in CIDR notation
    :param list_name: Name of the file to store the scan results
    """
    scan_command = f'zmap --cooldown-time=3 --bandwidth=5000K --probe-module=icmp_echoscan {ip_cidr} -o {list_name}'
    os.system(scan_command)

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
        operating_system = machine['scan'][target]['osmatch'][0]['name']

        return host_mac, operating_system

    except Exception as e:
        print(e)
        return 'Unknown', 'Unknown'

def os_detection(list_name):
    """
    Perform OS detection for the IP addresses in the given list.
    :param list_name: Name of the file containing the list of IP addresses
    """
    with open(list_name, "r") as f:
        ip_list = [ip.strip() for ip in f if ip.strip()]

    print(f'{len(ip_list)} hosts detected.\nDetecting OS .... \n')

    scan_results = []
    for i, ip in enumerate(ip_list, start=1):
        mac, detected_os = detect(ip)
        print(f'{i}: IP: {ip} | Mac: {mac} | OS: {detected_os}')
        scan_results.append({"IP": ip, "MAC": mac, "OS": detected_os})

    os.remove(list_name)

    with open("assets.json", "w") as write_file:
        json.dump(scan_results, write_file)

def main(ip_range):
    """
    Entry point of the script.
    :param ip_range: IP range to scan in CIDR notation
    """
    if os.geteuid() != 0:
        print('You need to be root to run this script', file=sys.stderr)
        sys.exit(1)

    list_name = "IPs_list.txt"
    scan(ip_range, list_name)
    os_detection(list_name)

def usage():
    exit("Usage: %s -n <CIDR: IP Range>" % sys.argv[0])

if __name__ == "__main__":
    try:
        network = sys.argv[2]
        main(network)
    except Exception as e:
        print(e)
        usage()
