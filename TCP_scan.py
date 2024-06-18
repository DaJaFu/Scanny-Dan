from scapy.all import *

#attempts TCP handshake with given ip:port
def tcp_handshake(port, ip, ack=False):
    out = [port]
    #declare syn packet with 0 bytes of data
    syn_packet=IP(dst=ip)/TCP(dport=int(port),flags='S')
    #declare ack packet with 0 bytes of data
    ack_packet = IP(dst=ip)/TCP(dport=int(port),flags='A')
    #declare fin packet with 0 bytes of data
    rst_packet = IP(dst=ip)/TCP(dport=int(port),flags='R')
    #sends packet to destination ip address and stores anything received
    if ack:
        response = sr1(ack_packet, timeout=2,verbose=0)
        #print(response.getlayer(IP).proto)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags=="R":
            out.append("Unfiltered")
        else:
            out.append("Filtered")
        
    response = sr1(syn_packet,timeout=2,verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
        #print(f"Received SYN-ACK from address {ip} over port {port}")
        send(rst_packet)
        out.append(True)
    else:
        out.append(False)
    return out
    
if __name__ == "__main__":
    print("Initiating test scan ... ")
    print(tcp_handshake(22,"127.0.0.1",True))