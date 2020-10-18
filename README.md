# alarm.py
# Jack Burns
# October 2020

Files: alarm.py

Usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]
       optional arguments: -h, --help; 
       -i, interface, network interface to sniff on (ex. -i en0 will sniff packets on a wireless interface)
       -r, pcap file, will read from a pcap file
       
Purpose: Run this script to detect FIN, NULL, or Xmas nmap scans. It can also detect nikto scans, and someone scanning for Server Message Block (SMB) protocol.
Additionally, it can detect and decode any username:password pairs sent in-the-clear with HTTP or FTP protocol.

Behavior: If an inncident is detected, the program will display:
ALERT #{incident_number}: #{incident} is detected from #{source IP address} (#{port number}!

Where incident_number is a running count on the number of incidences detected. Incident is either FIN, NULL, Xmas, SMB protocol, or Nikto scan.

If a username:password pair is detected, it will display 
ALERT #{incident_number}: Usernames and passwords sent in-the-clear ({port number}) (username:{username}, password:{password}).

If unable to read from network, or if there is a problem with the pcap file, the program will display the an error message and terminate.

Technologies: This program extensively uses the scapy module created by Philippe Biondi

Acknowledgments: This program is built off some starter code created by Ming Chow (github: mchow01)
