#!/usr/bin/env python3
import sys
import socket
from typing import List

#Get user input and return the data as a list of strings
def get_input() -> List[str]:
    port_input = input('Which port(s) would you like to scan? : ')
    return port_input.split(',')

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
#prints command line args for later usage
print(sys.argv)
port_scan('localhost',get_input())