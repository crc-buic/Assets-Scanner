import os
import sys
import nmap
import pymongo
from flask_restful import Api, Resource
from flask import request, Flask, jsonify
from concurrent.futures import ThreadPoolExecutor
from pymongo.errors import ServerSelectionTimeoutError


app = Flask(__name__)
api = Api(app)

class BaseAssetProcessor(Resource):

    def __init__(self, scan_enabled=True):
        try:
            # Include credentials in the connection string
            self.client = pymongo.MongoClient("mongodb://127.0.0.1:27017/")
            self.client.server_info()
            print("Connected to MongoDB successfully.")
        except ServerSelectionTimeoutError:
            print("Failed to connect to MongoDB. Check the connection details and try again.")
            sys.exit(1)

        self.db = self.client["netspection"]
        self.collection = self.db["assets"]
        self.scan_enabled = scan_enabled

    def process_assets(self, ip_list):
        scan_results = []

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.detect, ip) for ip in ip_list]

            for i, future in enumerate(futures, start=1):
                ip = ip_list[i - 1]
                mac, detected_os = future.result()

                if self.scan_enabled:
                    try:
                        result = self.collection.insert_one({"IP": ip, "MAC": mac, "OS": detected_os})
                        print(f'{i}: IP: {ip} | Mac: {mac} | OS: {detected_os} | MongoDB Inserted ID: {result.inserted_id}')
                        scan_results.append({"IP": ip, "MAC": mac, "OS": detected_os, "Status": "Success"})

                    except Exception as e:
                        print(f'{i}: IP: {ip} | Mac: {mac} | OS: {detected_os} \n MongoDB Insertion Failed. Error: {e}')
                        scan_results.append({"IP": ip, "MAC": mac, "OS": detected_os, "Status": "Failed"})

                else:
                    print(f'{i}: IP: {ip} | Mac: {mac} | OS: {detected_os}')
                    scan_results.append({"IP": ip, "MAC": mac, "OS": detected_os})

        return scan_results


class AssetScanner(BaseAssetProcessor):

    def get(self):
        ip_cidr = request.args.get('ip_cidr')

        if os.geteuid() != 0:
            print('You need to be root to run this script', file=sys.stderr)
            sys.exit(1)

        ip_list = self.discover_assets(ip_cidr)
        scan_results = self.process_assets(ip_list)

        response = {'ip list': ip_list, 'hosts detected': len(ip_list), 'scanned_results': scan_results}
        return jsonify(response)

    def discover_assets(self, ip_cidr):
        nm = nmap.PortScanner()
        nm.scan(ip_cidr, arguments='-sn')
        ip_list = [host for host in nm.all_hosts() if nm[host].state() == 'up']
        return ip_list

    def detect(self, target):
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


class AssetRetrieval(BaseAssetProcessor):

    def get(self):
        stored_data = list(self.collection.find({}, {'_id': 0}))
        response = {'stored_data': stored_data, 'total_records': len(stored_data)}
        return jsonify(response)


api.add_resource(AssetScanner, '/asset_scanner')
api.add_resource(AssetRetrieval, '/retrieve_assets')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=9999)
