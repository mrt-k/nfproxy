import os
import sys
import argparse
import subprocess
from scapy.all import *
from netfilterqueue import NetfilterQueue
import scapy_http.http
from utils import color


def http_proxy(pkt, http_payload):
    print(http_payload)


def process(pkt):
    packet = IP(pkt.get_payload())
    print(packet)
    if packet.haslayer('HTTP'):
        http_payload = packet['HTTP'].payload
        print("[*] Requesting for %s:%d => %s:%d" % (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport))
        http_proxy(packet, http_payload)
    else:
        pkt.accept()


def check_arg():
    """ Check argv """
    parser = argparse.ArgumentParser(description="http_proxy")
    parser.add_argument('--queue-num', type=int, help="queue ID of NFQUEUE target in iptables", default=20000)
    args = parser.parse_args()
    return args

def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(args.queue_num, process)

    iptables_setup_cmd = "iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num %s" % args.queue_num
    iptables_clear_cmd = "iptables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num %s" % args.queue_num

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
