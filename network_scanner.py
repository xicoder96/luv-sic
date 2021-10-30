#!/usr/bin/env python3
import scapy.all as scapy
import argparse

"""

"""


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip",
                        help="IP address to be scanned")
    options = parser.parse_args()

    if not options.ip:
        parser.error("Please enter a valid IP address")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_list.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return client_list


def print_scan_result(list):
    print("IP\t\t\tMac")
    for client in list:
        print(f"{client['ip']}\t\t{client['mac']}")


if __name__ == "__main__":
    options = get_arguments()
    scan_results = scan(options.ip)
    print_scan_result(scan_results)
