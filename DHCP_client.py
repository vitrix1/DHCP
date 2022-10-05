import time
from random import randint
from scapy.all import *
import binascii
import datetime
import sys

IP_RECEIVED = {}  # key:src_mac; val: 1.received ip, 2.xid, 3.lease time, 4.mac serv, 5.ip serv

class DHCPClient:
    def __init__(self):
        self.src_mac = str(RandMAC('3C:8B:7F:*:*:*'))
        self.xid = int(randint(10000000, 99999999))

    def lease_counter(self, lease_time, dst_mac, src_ip, dst_ip):
        half = round(lease_time * 0.5)
        quarter = round(lease_time * 0.25)
        while lease_time > 0:
            if lease_time == half:
                self.request(self.src_mac, dst_mac, src_ip, dst_ip, self.xid)
            elif lease_time == quarter:
                dst_mac = 'FF:FF:FF:FF:FF:FF'
                dst_ip = '255.255.255.255'
                self.request(self.src_mac, dst_mac, src_ip, dst_ip, self.xid)
            lease_time -= 1
            time.sleep(1)
        IP_RECEIVED.pop(self.src_mac)
        print(f'COULD NOT RENEW {src_ip}')
        raise SystemExit


    def discover(self, src_mac, xid):
        ether = Ether(src=src_mac, dst='FF:FF:FF:FF:FF:FF', type=0x800)
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(xid=xid,
                      chaddr=binascii.unhexlify(self.src_mac.replace(":", "")),
                      ciaddr='0.0.0.0')
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        dis = ether / ip / udp / bootp / dhcp
        try:
            sendp(dis, iface=INTERFACE, verbose=0)
        except OSError:
            print('The specified interface was not detected.')
            raise SystemExit
        offer = sniff(filter="udp and (port 68 or 67)", iface=INTERFACE, count=1, timeout=1)
        return offer

    def request(self, src_mac, dst_mac, src_ip, dst_ip, xid):
        ether = Ether(src=src_mac, dst=dst_mac, type=0x800)
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(xid=xid,
                      chaddr=binascii.unhexlify(self.src_mac.replace(":", "")),
                      ciaddr='0.0.0.0')
        dhcp = DHCP(options=[("message-type", "request"), "end"])
        req = ether / ip / udp / bootp / dhcp
        sendp(req, iface=INTERFACE, verbose=0)

        ack = sniff(filter="udp and (port 68 or 67)", iface=INTERFACE, count=1, timeout=1)

        number_of_request = 3
        while number_of_request > 0:
            if len(ack) > 0 and ack[0][DHCP].options[0][1] == 5 and \
                    ack[0][BOOTP].xid == self.xid:
                number_of_request = 0
                lease_time = int(ack[0][DHCP].options[2][1])
                lease_time_show = str(datetime.timedelta(seconds=lease_time))
                print(f'RECEIVED {ack[0][BOOTP].yiaddr} FROM {ack[0][IP].src} for',
                      lease_time_show)
                IP_RECEIVED[self.src_mac] = ack[0][BOOTP].yiaddr, str(self.xid), lease_time, \
                                            ack[0][Ether].src, ack[0][IP].src
                self.lease_counter(lease_time, ack[0][Ether].src, ack[0][BOOTP].yiaddr, ack[0][IP].src)
            else:
                number_of_request -= 1
                if number_of_request == 0:
                    print('NO ACK')

    def receive_ip(self):
        number_of_discover = 3
        while number_of_discover > 0:
            offer = self.discover(self.src_mac, self.xid)
            time.sleep(0.1)
            if len(offer) > 0 and offer[0][DHCP].options[0][1] == 2 and \
                    offer[0][BOOTP].xid == self.xid:
                number_of_discover = 0
                self.request(self.src_mac, offer[0][Ether].src, offer[0][BOOTP].yiaddr,
                             offer[0][IP].src, self.xid)
            else:
                number_of_discover -= 1
                if number_of_discover == 0:
                    print('NO OFFER')

def release_ip():
    for mac, value in IP_RECEIVED.items():
        ether = Ether(src=mac, dst=value[3], type=0x800)
        ip = IP(src=value[0], dst=value[4])
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(xid=int(value[1]),
                      chaddr=binascii.unhexlify(mac.replace(":", "")),
                      ciaddr=value[0])
        dhcp = DHCP(options=[("message-type", "release"), "end"])
        rel = ether / ip / udp / bootp / dhcp
        sendp(rel, iface=INTERFACE, verbose=0)
        time.sleep(0.3)
    print(f'{len(IP_RECEIVED)} IP RELEASED')
    IP_RECEIVED.clear()


def main():
    while True:
        instance_dict = {}
        instance = 0
        command = input('Count or q to escape and release ip:\n')
        if command.isdigit():
            count = int(command)
            for iteration in range(count):
                instance += 1
                instance_dict[instance] = DHCPClient
                ps = Thread(target=instance_dict[instance]().receive_ip, daemon=True)
                ps.start()
                time.sleep(0.6)
        else:
            release_ip()
            break

if __name__ == '__main__':
    if len(sys.argv) > 1:
        INTERFACE = sys.argv[1]
        main()
    else:
        print('Use: <name script> <iface>')

