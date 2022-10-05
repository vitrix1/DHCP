# DHCP Client for Windows
## About 
 This script is performing dhcp client's behavior and receiving IP addresses.
It uses standard DORA packets exchange. Also, after finish the work it sends 
a Release message to release the received IP. During work, it renews an IP address
according to the lease time.
##### ! Unfortunately, only launch on Windows is supported !
## Before start
You should install Python3, scapy library (pip install scapy) and 
[Npcap](https://npcap.com/).
## How to start
<name_script> <name_interface>
## Example
DHCP_Client.py Ethernet


