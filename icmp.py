import os
import sys
from scapy.all import *
from netfilterqueue import NetfilterQueue

#conf.verbose = 0
#conf.L3socket = L3RawSocket

def rw_echo_reply(pkt):
    ip = IP()
    icmp = ICMP()
    ip.src = pkt[IP].dst
    ip.dst = pkt[IP].src
    icmp.type = 0
    icmp.code = 0
    icmp.id = pkt[ICMP].id
    icmp.seq = pkt[ICMP].seq
    print("\t%s => %s" % (ip.src, ip.dst))
    data = pkt[ICMP].payload
    send(ip/icmp/data, verbose=0)

def process(pkt):
    packet = IP(pkt.get_payload())
    proto = packet.proto
    if proto is 0x01:
        print("[*] ICMP Packet Detected")
        if packet[ICMP].type is 8:
            print("[*] ICMP Echo Request Packet Detected")
            rw_echo_reply(packet)
    


def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process)

    try:
        nfqueue.run()
    except:
        print("Exiting...")
        # iptables reset
        
        sys.exit(1)

main()
