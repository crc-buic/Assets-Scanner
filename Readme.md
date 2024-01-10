
## User Manual: Network Scanner and OS Detector

### Overview
The Network Scanner and OS Detector is a Python script that allows you to perform network scanning and detect the operating system of the hosts within a given IP range. It utilizes the Zmap and Nmap tools to accomplish these tasks. The script generates a list of IP addresses within the specified range, performs network scanning using Zmap, and then detects the operating system of each host using Nmap. The results are stored in a JSON file for further analysis.

### Prerequisites
- Python 3.x
- Zmap
- Nmap
- `python-nmap` library (install using `pip install python-nmap`)

### Usage
To run the Network Scanner and OS Detector script, follow these steps:

1. Open a command prompt or terminal.
2. Navigate to the directory containing the script.
3. Run the script with the following command:

   ```
   python scan.py -n <CIDR: IP Range>
   ```

   Replace `<CIDR: IP Range>` with the desired IP range in CIDR notation. For example, `192.168.0.0/24` represents all IP addresses from `192.168.0.1` to `192.168.0.254`.

4. Make sure to run the script with administrative privileges or as a root user, as it requires certain permissions for network scanning.

### Output
The Network Scanner and OS Detector script provides the following outputs:

- **Console Output**: During the execution of the script, it displays the progress and results on the console. It shows the IP address, MAC address (if detected), and the detected operating system for each host within the specified IP range.

- **JSON File**: After scanning and OS detection, the script generates an `assets.json` file. This file contains a JSON-formatted list with the details of each host, including the IP address, MAC address, and detected operating system. You can use this file for further analysis or processing.

### Notes
- Ensure that you have the necessary permissions and dependencies installed to run the script successfully.
- The script uses the Zmap tool for network scanning and Nmap for OS detection. Make sure these tools are properly installed and available in the system's environment path.
- The `python-nmap` library is required for interfacing with Nmap in Python. If not already installed, you can install it using `pip install python-nmap`.
- The execution time of the script depends on the size of the IP range and the network speed. It may take some time to complete the scanning and OS detection process.
- The script is optimized for efficiency and reliability. However, it is recommended to review and customize the script according to your specific requirements and network environment.

### Troubleshooting
- If you encounter any errors or issues during the execution of the script, ensure that you have met the prerequisites and followed the usage instructions correctly.
- Verify that Zmap and Nmap are installed and working properly. Test them individually to ensure they are functioning as expected.
- If you are experiencing problems with the `python-nmap` library, make sure it is installed correctly and the version is compatible with your Python environment.

