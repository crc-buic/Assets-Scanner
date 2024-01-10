import os
import sys
# pip install python-nmap
import nmap
import json


list_name = "IPs_list.txt"

# ip_cidr = 172.16.221.0/24
def scan(ip_cidr):
    # Zmap Scanning
    scan_command =  f'zmap --cooldown-time=3 --bandwidth=5000K --probe-module=icmp_echoscan {ip_cidr} -o {list_name}' 
    #print(scan_command)
    os.system(scan_command)
    return 1

def detect(target):
    try:
        # print("\n")
        # print(target)
        nm = nmap.PortScanner()

        # old --> machine = nm.scan(target, arguments='-O') // Very slow 
        # print("\nbefore machine")

        machine = nm.scan(target, arguments='-v -sSU -pT:20-25,80,443-445,U:54321-54330 -O')
        
   
        # Check if the mac is there or not by checking the length of addresses in the host scan result
        # i.e len(machine['scan'][target]['addresses']), usually there are two keys in it, one is the ipv4 and the other is mac. So if the length is only 1,
        # then it means only ipv4 is present and no mac address is in the list.
        
        # print(machine['scan'][target]) 
        # print(machine['scan'][target]['addresses']) // ipv4 and Mac
        # print(len(machine['scan'][target]['addresses'])) 
        # print(machine['scan'][target]['addresses']['mac']) // MAC
        # print(machine['scan'][target]['osmatch'][0]['name']) // OS


        if len(machine['scan'][target]['addresses']) == 1:
            # print("no mac")
            # return 0,0
            host_mac = 'Unknown'

        else:
            host_mac = machine['scan'][target]['addresses']['mac']

        # print(machine['scan'][target]['osmatch'][0]['osclass'][0]['osfamily'])

        operating_system =  machine['scan'][target]['osmatch'][0]['name']

        # machine['scan'][target]['osmatch'][0]['osclass'][0]['osfamily'] // OS without version [Not specific]

        return host_mac,operating_system

    except Exception as e:
        print(e)
        return 'Unknown', 'Unknown'


def os_detection():
    f = open(list_name, "r")
    ip_list =  f.read().split('\n')
    while("" in ip_list) :
        ip_list.remove("")

    print(f'{len(ip_list)} hosts detected.\nDetecting OS .... \n')
    i = 0
    scan_results = []
    for ip in ip_list:
        i +=1

        # detect method will try to detect mac and os for the given ip, if detection isn't possible then a tuple with 0,0 will be returned.
        mac,detected_os = detect(ip)


        # 1: IP: 172.16.221.2 | Mac: E0:1A:EA:2E:85:7F | OS: Linux 3.2 - 4.9
        print(f'{i}: IP: {ip} | Mac: {mac} | OS: {detected_os}')

        scan_results.append({"IP": ip, "MAC": mac, "OS": detected_os})

        
        '''
        x = {
            '172.16.221.166': [{
                'Mac': '2',
                'OS': '123'
            }],
            
            '172.16.221.126': [{
            'Mac': 'test1',
            'OS': 'tests'
        }],
        } '''


    # print(json.dumps(scan_results))

    # Empty last scanned IPs list.
    os.remove(list_name) 


    # writing data to json file
    with open("assets.json", "w") as write_file:
        json.dump(scan_results, write_file)
        return 1


def main(ip_range):

    if os.geteuid() != 0:
        print('You need to be root to run this script', file=sys.stderr)
        sys.exit(1)  

    # first of all scan the network to find hosts
    if scan(ip_range):
        # once scanning is done, read the output file of hosts and detect os for each host
        if os_detection():
            print ("\nResults stored in assets.json file!\n")


def usage():
    exit("Usage: %s -n <CIDR: IP Range>" % sys.argv[0])


if __name__ == "__main__":
    try:
        network = sys.argv[2]
        main(network)
    except Exception as e:
        print(e)
        usage()

