#!/usr/bin/env python3
import sys
import socket
from typing import List

print(sys.argv)

#attempt to discover what service the specified port is running
def get_service_name(port):
    try:
        service = socket.getservbyport(port)
        return service
    except:
        return "Unknown"

#Get user input and return the data as a list of strings
def get_input() -> List[str]:
    #if the argument '-r' is passed in the command line, then use the given range of ports
    if len(sys.argv) > 1 and sys.argv[1] == '-r':
        try:
            print('Input type: Port Range')
            port_range = sys.argv[2].split('-')
            port_input = range(int(port_range[0]),int(port_range[1])+1)
            return port_input
        except:
            print('ERROR! Expected range of ports, seperated by a "-" Please try again.')
    #if there is no arguement given, then default to a manual input
    else:
        print('Defaulting to manual port input')
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
        print(f"Port is running service: {get_service_name(port)}")
        sock.close()

#if this script is the main program being run, attempt to scan ports using get_input
if __name__ == "__main__":
    try:
        port_scan('localhost',get_input())
    except:
        print(f'ERROR! Port input received: {get_input()}')