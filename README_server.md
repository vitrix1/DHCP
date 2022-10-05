# DHCP Server for Windows
## About
This script performs the role of a DHCP server and issues IP addresses using the standard data packet exchange.
Also, the server can record logs and monitor the lease time, release the IP after the lease time expires, or does
the same when receiving a Release message from the client.
## Before start
You should install scapy (pip install scapy) and [Npcap](https://npcap.com/).  
You should also create a configuration file 'dhcp_conf.txt' in the same directory as the script.  
You can specify several subnets. Each subnet will have its own server running.   
Example of the file:  
Subnet 1  
subnet=10.10.10.0/24  
lease time=86400  
interface=Ethernet2  
mac=02:00:4C:4F:4F:50    
Subnet 2   
subnet=172.16.0.0/24  
lease time=3600  
interface=Ethernet  
mac=02:00:4C:4F:4F:40
## How it works
The server takes for itself the first network address from the subnet (for example: 10.10.10.1/24).
It uses this address as the default gateway address and the name of the dhcp server.
Then it determines the remaining addresses in the pool (offered_ip_list) and starts listening to the interface.
If it receives a Discover message, it starts the standard packet exchange.
If it receives a Request to renew the IP address, it checks the xid and ip address and, if it finds, updates the IP address.
If it receives a Release, it will release the IP address and then issue it again.
It also tracks the lease time of the issued IP addresses, and if the client does not renew the IP address, the server releases the IP address.
A file with logs will appear in the folder with the script.
## How to start
1. To create the configuration file 'dhcp_conf.txt'.
2. To create subnet in this file.
3. To start the script:  
in the cmd <name_script>   
or by double-clicking on the script.