from scapy.all import *
import binascii
import datetime
import ipaddress
import time

ISSUED_IP = {}


class DHCPServer:
    def __init__(self, network_settings):
        self.src_mac = network_settings['mac']
        self.net_ip = network_settings['subnet']
        self.lease_time = network_settings['lease time']
        self.interface = network_settings['interface']
        self.subnet = ipaddress.ip_network(self.net_ip)
        self.mask = ipaddress.ip_interface(self.net_ip).netmask
        self.lease_time_show = str(datetime.timedelta(seconds=self.lease_time))
        self.offered_ip_list = list(self.subnet.hosts())

    def offer(self, dst_mac, xid):
        ether = Ether(src=self.src_mac, dst=dst_mac, type=0x800)
        ip = IP(src=self.offered_ip_list[0], dst=self.offered_ip_list[1])
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(xid=xid,
                      chaddr=binascii.unhexlify(dst_mac.replace(":", "")),
                      yiaddr=self.offered_ip_list[1])
        dhcp = DHCP(options=[("message-type", "offer"),
                             ("server_id", self.offered_ip_list[0]),
                             ("lease_time", self.lease_time),
                             ("subnet_mask", self.mask),
                             ("router", self.offered_ip_list[0]),
                             ("name_server", self.offered_ip_list[0]), "end"])
        off = ether / ip / udp / bootp / dhcp
        sendp(off, iface=self.interface, verbose=0)

    def ack(self, dst_mac, xid, offered_ip):
        ether = Ether(src=self.src_mac, dst=dst_mac, type=0x800)
        ip = IP(src=offered_ip[0], dst=offered_ip[1])
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(xid=xid,
                      chaddr=binascii.unhexlify(dst_mac.replace(":", "")),
                      yiaddr=offered_ip[1])
        dhcp = DHCP(options=[("message-type", "ack"),
                             ("server_id", offered_ip[0]),
                             ("lease_time", self.lease_time),
                             ("subnet_mask", self.mask),
                             ("router", offered_ip[0]),
                             ("name_server", offered_ip[0]), "end"])
        ack = ether / ip / udp / bootp / dhcp
        sendp(ack, iface=self.interface, verbose=0)

    def dhcp_server(self):
        print('DHCP server start.')
        while len(self.offered_ip_list[1:]) > 0:
            TMP_PRMTS = {}  # The temporary parameters of packets
            while True:
                pkt = sniff(filter="udp and (port 68 or 67)",
                            iface=self.interface,
                            count=1)
                # if the pkt is a Discover
                if pkt[0][DHCP].options[0][1] == 1:
                    self.offer(pkt[0][Ether].src, pkt[0][BOOTP].xid)
                    # save parameters of a Discover
                    TMP_PRMTS[pkt[0][Ether].src] = self.offered_ip_list[1], pkt[0][BOOTP].xid
                # if the pkt is our Request
                elif TMP_PRMTS.get(pkt[0][Ether].src) != None and pkt[0][DHCP].options[0][1] == 3 and \
                        pkt[0][BOOTP].xid == TMP_PRMTS[pkt[0][Ether].src][1]:
                    # issue an ip
                    if ISSUED_IP.get(pkt[0][Ether].src) == None:
                        issue_ip_time = time.time()
                        self.ack(pkt[0][Ether].src, pkt[0][BOOTP].xid, self.offered_ip_list[:2])
                        print(f'ISSUED {self.offered_ip_list[1]} TO {pkt[0][Ether].src} FOR',
                              self.lease_time_show)
                        ISSUED_IP[pkt[0][Ether].src] = self.offered_ip_list[1], pkt[0][BOOTP].xid, issue_ip_time
                        log_writer(pkt[0][Ether].src, 'ISSUED', self.net_ip.split('/')[0])
                        self.offered_ip_list.pop(1)
                    # renew an ip
                    elif ISSUED_IP.get(pkt[0][Ether].src) != None:
                        issue_ip_time = time.time()
                        self.ack(pkt[0][Ether].src, pkt[0][BOOTP].xid, [self.offered_ip_list[0], pkt[0][IP].src])
                        print(f'RENEWED {ISSUED_IP[pkt[0][Ether].src][0]} TO {pkt[0][Ether].src} FOR',
                              self.lease_time_show)
                        ISSUED_IP[pkt[0][Ether].src] = pkt[0][IP].src, pkt[0][BOOTP].xid, issue_ip_time
                        log_writer(pkt[0][Ether].src, 'RENEWED', self.net_ip.split('/')[0])
                    # else:
                    #     print('NO REQUEST')
                # if the pkt is a Release
                elif pkt[0][DHCP].options[0][1] == 7 and \
                        ISSUED_IP.get(pkt[0][Ether].src) != None and \
                        pkt[0][BOOTP].xid == ISSUED_IP[pkt[0][Ether].src][1]:
                    self.offered_ip_list.append(pkt[0][IP].src)
                    print(f'{pkt[0][IP].src} RELEASED')
                    log_writer(pkt[0][Ether].src, 'RELEASED', self.net_ip.split('/')[0])
                    ISSUED_IP.pop(pkt[0][Ether].src)
                # else:
                #     print('ERROR')
        print('NO FREE ADDRESSES')
        log_writer(pkt[0][Ether].src, 'NO FREE ADDRESSES', self.net_ip.split('/')[0])


if __name__ == '__main__':
    def log_writer(mac, event, subnet):
        issue_ip_time = time.time()
        current_date = str(datetime.datetime.fromtimestamp(issue_ip_time))
        with open(f'dhcp_network logs_{subnet}.txt', 'a') as logs:
            logs.write(current_date + ' ' + event + ' ' + str(ISSUED_IP[mac][0]) + '\n')

    def lease_watcher(lease_time, subnet):
        while True:
            current_time = time.time()
            for key, value in list(ISSUED_IP.items()):
                if (current_time - value[2]) > lease_time:
                    print(f'{value[0]} RELEASED BY TIME')
                    log_writer(key, 'RELEASED BY TIME', subnet)
                    ISSUED_IP.pop(key)

    network_dict = {}
    with open('dhcp_conf.txt', encoding='utf-8') as f:
        config = f.read().rstrip().split('Subnet ')
        config_list = [subnet.rstrip().split('\n') for subnet in config]
        config_list.pop(0)
        network_counter = len(config_list)
        for network in config_list:
            network_dict[int(network[0])] = {'subnet': network[1].split('=')[1],
                                             'lease time': int(network[2].split('=')[1]),
                                             'interface': network[3].split('=')[1],
                                             'mac': network[4].split('=')[1]}

    instance_dict = {}
    instance = 0
    for iteration in range(len(network_dict)):
        instance += 1
        instance_dict[instance] = DHCPServer(network_dict[instance])
        server = Thread(target=instance_dict[instance].dhcp_server)
        server.start()
        watcher = Thread(target=lease_watcher, args=(network_dict[instance]['lease time'],
                                                     network_dict[instance]['subnet'].split('/')[0]))
        watcher.start()

