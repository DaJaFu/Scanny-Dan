from scapy.all import *

def udp_scan(ip, port)->bool:
    icmp_codes = {
                0:"Net Unreachable.",
                1:"Host is Unreachable.",
                2:"Protocol is Unreachable",
                3:"Port is Unreachable",
                4:"Fragmentation is needed and 'Do not Fragment' was set.",
                5:"	Source route failed.",
                6: "Destination network is unknown.",
                7: "Destination host is unknown.",
                8: "Source host is isolated.",
                9: "Communication with destination network is administratively prohibited.",
                10: "Communication with destination host is administratively prohibited.",
                11: "Destination network is unreachable for type of service.",
                12: "Destination host is unreachable for type of service.",
                13:	"Communication is administratively prohibited.",
                14: "Host precedence violation.",
                15:	"Precedence cutoff is in effect."
                }

    if port != 53:
        pck = IP(dst=ip)/UDP(dport=port)
    else:
        pck = IP(dst=ip)/UDP(dport=port)/DNS()
        print("Sending DNS req to port 53")
    rsp=sr1(pck,timeout=2)
    if rsp and rsp.haslayer(ICMP):
        cdnum = rsp.getlayer(ICMP).code
        print(f"ICMP Code {cdnum}: {icmp_codes.get(cdnum)}")

udp_scan("127.0.0.1",53)