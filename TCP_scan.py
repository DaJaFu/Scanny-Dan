from scapy.all import *

'''
TCP Scan takes in a port number as an integer, an ip address in decimal format,
and "ack" which is a bool that if true only performs an ack scan.

This version is set up to be used via python 'threading' library.

Output includes Port number, Status (Open/Closed), filtered (True/False), and log, which contains
all the packets sent to and received by the port, with a S(ent) or R(eceived).
'''

#attempts TCP handshake with given ip:port
def tcp_handshake(port, ip, results, ack=False,verbose=0):
    out = {"port":port,"status":"closed","filtered":None,"log":[]}
    if verbose>0:print(f"SCAN: Beginning scan on port {port}, on IPv4 address: {ip}")
    #construct TCP syn, ack, and rst packets with 0 bytes of data.
    syn_packet=IP(dst=ip)/TCP(dport=int(port),flags='S')
    ack_packet = IP(dst=ip)/TCP(dport=int(port),flags='A')
    rst_packet = IP(dst=ip)/TCP(dport=int(port),flags='R')
    
    #sends packet to destination ip address and stores anything received
    if ack:
        response = sr1(ack_packet, timeout=2,verbose=verbose)
        if verbose>0:print(f"SCAN: Sent ack packet to port {port}, awaiting response...")
        out["log"].append(("S",ack_packet))
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags=="R":
            out["filtered"]=False
            out["log"].append(("R",response))
            if verbose>0:print(f"SCAN: Reset packet received from port {port}. Network is likely unfiltered.")
        elif not response:
            if verbose>0:print(f"SCAN: No response received from port {port}, likely to be filtered.")
            out["filtered"]=True
        else:
            print(f"{response} received from port {port}")
    else:
        response = sr1(syn_packet,timeout=2,verbose=verbose)
        if verbose>0:print(f"SCAN: Sent syn packet to port {port}, awaiting response...")
        out["log"].append(("S",syn_packet))
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
            if verbose>0:print(f"SCAN: Received {response.getlayer(TCP).flags} from address {ip} over port {port}")
            out["log"].append(("R",response))
            out["status"]="open"
            send(rst_packet,verbose=0)
            if verbose>0:print(f"SCAN: Sent reset packet to port {port}")
            out["log"].append(("S",rst_packet))
        elif not response:
            if verbose>0:print(f"SCAN: No response received from port {port}")
    results.append(out)
    return out
    
if __name__ == "__main__":
    print("Initiating test scan ... ")
    print(tcp_handshake(22,"127.0.0.1",True))
    print(tcp_handshake(22,"127.0.0.1",False))