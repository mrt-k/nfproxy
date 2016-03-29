import os
import sys
import subprocess
import argparse
from scapy.all import *
from netfilterqueue import NetfilterQueue
from utils import color


def fake_dns_reply(pkt, qname):
    ip = IP()
    udp = UDP()
    ip.src = pkt[IP].dst
    ip.dst = pkt[IP].src
    udp.sport = pkt[UDP].dport
    udp.dport = pkt[UDP].sport

    solved_ip = args.fake_ip_addr
    qd = pkt[UDP].payload
    dns = DNS(id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)
    dns.qd = qd[DNSQR]
    dns.an = DNSRR(rrname = qname, ttl = 3600, rdlen = 4, rdata = solved_ip)
    dns.ns = DNSRR(rrname = qname, ttl = 3600, rdlen = 4, rdata = solved_ip)
    dns.ar = DNSRR(rrname = qname, ttl = 3600, rdlen = 4, rdata = solved_ip)
    print("\t[*] Sending to %s:%s" % (ip.dst, udp.dport))
    send(ip/udp/dns, verbose=0)


def process(pkt):
    packet = IP(pkt.get_payload())
    proto = packet.proto
    if proto is 0x11:
            if packet[UDP].dport is 53:
                dns = packet[UDP].payload
                qname = dns[DNSQR].qname
                print((color.GREEN + "[*] Requesting for " + color.RED + "%s" + color.END) % qname)
                fake_dns_reply(packet, qname)
    

def check_arg():
    """ Check argv """
    parser = argparse.ArgumentParser(description="dns_fake")
    parser.add_argument('fake_ip_addr', help="fake ip address", nargs=None)
    parser.add_argument('--ttl', type=int, help="ttl", default=3600)
    parser.add_argument('--queue-num', type=int, help="queue ID of NFQUEUE target in iptables", default=10000)
    args = parser.parse_args()
    return args

def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(args.queue_num, process)

    iptables_setup_cmd = "iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num %s" % args.queue_num
    iptables_clear_cmd = "iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num %s" % args.queue_num

    try:  
        if subprocess.call(iptables_setup_cmd, shell=True) == 0:
            print((color.GREEN + "[*] Executing : '%s'" + color.END) % iptables_setup_cmd)
            print(color.GREEN + "[*] Running" + color.END)
            nfqueue.run()
        else:
            print(color.RED + "[!]Could not iptables configuration..." + color.END)
            sys.exit(1)
    except:
        print(color.GREEN + "[*] Exiting..." + color.END)
        print((color.GREEN + "[*] Executing : '%s'" + color.END) % iptables_clear_cmd)
        subprocess.call(iptables_clear_cmd, shell=True)
        sys.exit(1)

args = check_arg()
main()
