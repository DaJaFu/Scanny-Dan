#!/usr/bin/env python3
import sys
import socket
from typing import List
print('+------Scanny-Dans-Port-Scanner------+')
#print(sys.argv)

usage = open('usage.txt','r')

#attempt to discover what service the specified port is running
def get_service_name(port):
    try:
        service = socket.getservbyport(port)
        return service
    except:
        return "Unknown"

#Get user input and return the data as a list of strings
def get_input() -> List[str]:
    port_list = []
    for argument in sys.argv:
        if argument in ('-f','--file'):
            port_f = open(str(sys.argv[2]),'r')
            for port in port_f.read().split(','):
                port_list.append(port)
        elif argument in ('-p','--port'):
            port_list.append(str(sys.argv[2]))
        elif argument in ('-r','--range'):
            range_l = str(sys.argv[2]).split('-')
            for i in range(int(range_l[0]),int(range_l[1])+1):
                port_list.append(i)
        elif argument in ('-h','--help'):
            print(usage.read())
            return 'h'
    return port_list

#defining the port scan function, and setting parameters.
def port_scan(target_ip: str, ports: List[str]):
    #iterating over all the desired ports in the target network and attempting to open a socket with them.
    for port_string in ports:
        #first, attempt to translate the string into an integer
        try:
            port = int(port_string)
        #if that doesn't work, skip the item in the list and print an error message.
        except ValueError:
            print(f"ERROR Expected integer: {port_string}")
            print('-------------')
            continue
        #creating a socket using ipv4 (AF_INET)
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #if the socket can't connect to a port within this time allotment, quit
        sock.settimeout(1)
        #attempt to connect to the current port, if unable, return that it's closed
        try:
            sock.connect((target_ip,port))
            print(f"Port {port} is open.")
        except:  
            print(f"Port {port} is closed.")
        print(f"Port is running service: {get_service_name(port)}")
        print('-------------')
        sock.close()

#if this script is the main program being run, attempt to scan ports using get_input
if __name__ == "__main__":
    if get_input() != 'h':    
        try:
            port_scan('localhost',get_input())
        except:
            print(f'ERROR! Port input received: {get_input()}')
            print(usage.read())