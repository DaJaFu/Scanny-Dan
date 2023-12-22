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
        return socket.getservbyport(port)
    except:
        return "Unknown"

def get_ip():
    #simultaneously get ip and validate.
    if len(sys.argv) > 2:
        ip_address = sys.argv[1]
        try:
            socket.inet_aton(ip_address)
            return ip_address
        except socket.error:
            try:
                socket.inet_aton(socket.gethostbyname(ip_address))
                print(f'Detected host: {socket.gethostbyname(ip_address)} from {ip_address}')
                print('-------------')
                return ip_address
            except socket.error:
                print('Something went wrong, host not detected!')
                print('--------------------')
    return False

#get input type through command line input
def get_type() -> str:
    arg_dict = {'-f':'f','--file':'f','-p':'p','--port':'p','-r':'r','--range':'r','-h':'h','--help':'h'}
    if sys.argv[1] in arg_dict:
        return arg_dict.get(sys.argv[1])
    elif sys.argv[2] in arg_dict:
        return arg_dict.get(sys.argv[2])
    else:
        return None

#open a file specified in the command line and search for valid port numbers
def parse_file(filename)->List[str]:
    file = open(filename,'r')
    read_file = file.read()
    port_list = []
    current_port = ''
    for i in range(len(read_file)):
        #print(read_file[i])
        #if the current iterator is equal to the len of the file, quit
        if i == len(read_file):
            break
        #if current character can be converted to an integer (is an int string)
        try:
            int(read_file[i])
            #print(read_file[i])
            #add current character to the current port string
            current_port = current_port + str(read_file[i])
        except:
            continue
        #if the next character is a number then skip to it
        if len(current_port)<5:
            try:
                #print(read_file[i+1])
                int(read_file[i+1])
            except:
                #print(current_port)
                port_list.append(current_port)
                current_port = ''
        else:
            port_list.append(current_port)
            current_port = ''
    return port_list

#print(parse_file(sys.argv[2]))

#Parse user input and return data as a list of strings
def get_ports() -> List[str]:
    port_list = []
    if get_type() == 'f':
        port_list = parse_file(sys.argv[3])
    elif get_type() == 'p':
        port_list.append(str(sys.argv[3]))
    elif get_type() == 'r':
        range_l = str(sys.argv[3]).split('-')
        for i in range(int(range_l[0]),int(range_l[1])+1):
            port_list.append(i)
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
        sock.settimeout(10)
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
    if get_type() != 'h' and get_ip() == False:
        print('ERROR! Invalid ip address. Check input and try again!')
    if get_type() == None:
        print(f'ERROR! {" ".join(sys.argv)} is not acceptable input. Try using -h for more info.')
    elif get_type() == 'h':
        print(usage.read())
    else:
        print(f'Scanning port(s): {get_ports()}, on host: {get_ip()}')
        port_scan(get_ip(),get_ports())