import socket
import json
from scapy.all import *

'''
This script will attempt to determine the given ports Transport Protocol,
this is useful as it gives the scanner a clearer image of what scripts to use,
which reduces resource usage. 
This also allows for a better analysis of vulnerabilities.
'''

def packet_check(host,port):
    tcp_packet = IP(dst=host)/TCP(dport=port,flags="S")
    response = sr1(tcp_packet,timeout=2)
    if response and response.haslayer(TCP):
        protocol = response.getlayer(IP).proto
        with open("protocol_values.json","r") as file:
            dct = json.load(file)
            if str(protocol) in dct:
                return (dct.get(str(protocol)),True)
        return protocol
    else:
        try:
            return response.show
        except:
            print("SOMETHING BROKE")
    
for i in range(1,100):
    print(packet_check("127.0.0.1",int(i)))