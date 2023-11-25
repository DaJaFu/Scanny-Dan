#!/usr/bin/env python3

import socket


#defining the port scan function, and setting parameters.
def port_scan(target_ip, port):
    #iterating over all the desired ports in the target network and attempting to open a socket with them.
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((target_ip,port))
        print "Port is open."
    except:  
        print "Port is closed."
    


port_scan('localhost',input("Which port would you like to scan? : "))
