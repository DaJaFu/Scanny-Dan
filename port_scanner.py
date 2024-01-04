#!/usr/bin/env python3
import sys
import socket
import csv
import argparse
import threading
from typing import List
print('+------Scanny-Dans-Port-Scanner------+')
#print(sys.argv)

max_threads = 50
result = []

#attempt to discover what service the specified port is running
def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def get_ip():
    if len(sys.argv) > 2:
        ip_address = sys.argv[2]
        #validate ip address
        try:
            socket.inet_aton(ip_address)
            return ip_address
        except socket.error:
            #if ip is not valid, attempt to convert hostname into ip address
            try:
                socket.inet_aton(socket.gethostbyname(ip_address))
                print(f'Detected host: {socket.gethostbyname(ip_address)} from {ip_address}')
                print('-------------')
                return ip_address
            except:
                print('Something went wrong, host not detected!')
                print('--------------------')
    return False
host = get_ip()

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

#get input type and ports through command line input
def commandline_parse() -> str:
    parser = argparse.ArgumentParser(description="Your program description here.")
    parser.add_argument('hostname',help='Hostname to scan.')
    parser.add_argument('ports',nargs='?',help='Single port, range of ports, or text file.')
    parser.add_argument('-f', '--file',action='store_true', help='File argument')
    parser.add_argument('-p', '--port',action='store_true', help='Port argument')
    parser.add_argument('-r', '--range',action='store_true', help='Range argument')
    args = parser.parse_args()

    port_list = []

    if args.file:
        #print('file')
        port_list = parse_file(args.ports)
        return 'f', port_list
    elif args.port:
        #print('port')
        port_list.append(args.ports)
        return 'p', port_list
    elif args.range:
        #print('range')
        range_l = str(sys.argv[3]).split('-')
        for i in range(int(range_l[0]),int(range_l[1])+1):
            port_list.append(i)
        return 'r', port_list
    else:
        return None

def port_scan(host: str, port: List[str], results_list:list):
    try:
        int(port)
    except ValueError:
        print(f"ERROR Expected integer - Received: {port}")
        print('-------------')
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(6)
        sock.connect((host,port))
        print(f"Port {port} is open.")
        print(f"Port is running service: {get_service_name(port)}")
        print('-------------')
        sock.close()
        results_list.append((port , 'Open'))
    except socket.timeout:  
        print(f"Port {port} timed out, possibly closed.")
        print(f"Port is running service: {get_service_name(port)}")
        print('-------------')
        sock.close()
        results_list.append((port , 'Timed Out'))
    except socket.error as e:
        print(f"Error connecting to port {port}: {e}")
        print(f"Port is running service: {get_service_name(port)}")
        print('-------------')
        sock.close()
        results_list.append((port , f'Error: {e}'))

#since threading makes the output look ugly, this exports it into a csv instead.
def export_csv(results:List[str],output_filename):
    with open(output_filename, 'w', newline='') as csvfile:
        fieldnames = ['Port ', ' Status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for port, status in results:
            writer.writerow({'Port ': port, ' Status': status})

    print(f'File: {output_filename}, has been succesfully generated.')

def thread_scan(host:str,ports:List[str]):
    threads = []
    results_list = []

    for port in ports:
        port_number = int(port)

        #sets the maximum number of threads equal to 'max_threads'
        while threading.active_count() > max_threads:
            #waits until a thread is availible to continue.
            pass

        thread = threading.Thread(target=port_scan,args=(host,port_number,results_list))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    results = sorted(results_list, key=lambda x: x[0])
    return results
        
#if this script is the main program being run, attempt to scan ports using get_input
if __name__ == "__main__":
    commandline_results = commandline_parse()
    input_type = commandline_results[0]
    ports = commandline_results[1]
    port_range_str = '-'.join([str(ports[0]),str(ports[len(ports)-1])])
    if not host:
        print('ERROR! Invalid ip address. Check input and try again!')
    if input_type == None:
        print(f'ERROR! {"-".join(sys.argv)} is not acceptable input. Try using -h for more info.')
    else:
        print(f'Scanning port(s): {port_range_str}, on host: {host}')
        print('--------------------------')
        if len(ports) > 100:
            export_csv(thread_scan(host,ports),'scan_test.csv')
        else:
            for port in ports:
                port_scan(host,port,result)