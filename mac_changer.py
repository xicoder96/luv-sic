#!/usr/bin/env python3
import subprocess
import re
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface",
                        help="interface to change mac address")
    parser.add_argument("-m", "--mac", dest="new_mac",
                        help="value of new mac address")

    options = parser.parse_args()
    if not options.interface:
        parser.error("Please enter interface, use --help for more information")
    elif not options.new_mac:
        parser.error(
            "Please enter new MAC address use --help for more information")

    return options


def change_mac(interface, new_mac):
    print(f"[+] Changing mac address for {interface} to {new_mac}")
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_result = str(subprocess.check_output(
        ["sudo", "ifconfig", interface]))
    search_result = re.search(
        r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if search_result:
        return search_result.group(0)
    else:
        print("[-] Could not read mac address")


if __name__ == "__main__":
    options = get_arguments()
    current_mac = get_current_mac(options.interface)
    print(f"Current Mac:{current_mac}")
    change_mac(options.interface, options.new_mac)
    current_mac = get_current_mac(options.interface)
    if current_mac == options.new_mac:
        print(f"[+] MAC address was successfully changed to {current_mac}")
    else:
        print("[-] MAC address did not change")
