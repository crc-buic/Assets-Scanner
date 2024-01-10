from flask import request, Flask, Response
from flask_restful import Api, Resource
from flask_jsonpify import jsonify

import os
import sys
import nmap
from concurrent.futures import ThreadPoolExecutor


app = Flask(__name__)
api = Api(app)

class AssetScanner(Resource):
    def get(self):
        ip_cidr = request.args.get('ip_cidr')
        """
        Entry point of the script.
        :param ip_cidr: IP range to scan in CIDR notation
        """
        
        if os.geteuid() != 0:
            print('You need to be root to run this script', file=sys.stderr)
            sys.exit(1)
        ip_list = self.discover_assets(ip_cidr)

        scan_results = []

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.detect, ip) for ip in ip_list]

            for i, future in enumerate(futures, start=1):
                ip = ip_list[i-1]
                mac, detected_os = future.result()
                print(f'{i}: IP: {ip} | Mac: {mac} | OS: {detected_os}')
                scan_results.append({"IP": ip, "MAC": mac, "OS": detected_os})

        response = {'ip list': ip_list , 'hosts detected': len(ip_list), 'scanned_results': scan_results}
        # with open("assets.json", "w") as write_file:
        #     json.dump(scan_results, write_file)
        
        return jsonify(response)

    def discover_assets(self, ip_cidr):
        """
        Discover assets on the network using Nmap.
        :param ip_cidr: IP range in CIDR notation
        :return: List of IP addresses
        """
        nm = nmap.PortScanner()
        nm.scan(ip_cidr, arguments='-sn')
        ip_list = [host for host in nm.all_hosts() if nm[host].state() == 'up']
        return ip_list


    def detect(self, target):
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



api.add_resource(AssetScanner, '/asset_scanner')

if __name__ == '__main__':
    # app.run(debug=True)
    app.run(host = "0.0.0.0", port = 9999)
