#!/usr/bin/env python3
import sys
import time
import socket
import csv
import argparse
import threading
from typing import List
print('+------Scanny-Dans-Port-Scanner------+')
#print(sys.argv)

#filename for csv export (file name must end in .csv)
export_filename = 'scan_test.csv'

#maximum threads to be used
max_threads = 50

#estimate what service is running on a given port.
def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

#gathers ip address from command line input, validates, and converts from hostname
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

#get input type, ports, and other output modifiers from command line
def commandline_parse():
    parser = argparse.ArgumentParser(description='Dannys port scanner, try looking at the readme for more info, thanks for checking it out! https://github.com/DaJaFu/Scanny-Dan')
    parser.add_argument('hostname',help='Hostname to scan.')
    parser.add_argument('ports',nargs='?',help='Single port, range of ports, or text file.')
    input_type = parser.add_mutually_exclusive_group()
    input_type.add_argument('-f', '--file',action='store_true', help='File argument.')
    input_type.add_argument('-p', '--port',action='store_true', help='Port argument.')
    input_type.add_argument('-r', '--range',action='store_true', help='Range argument.')
    parser.add_argument('-v', '--verbose',action='store_true',help='Verbose Scan argument.')
    parser.add_argument('-e','--export',action='store_true',help='Export to csv argument.')
    args = parser.parse_args()
    #print(args)

    port_list = []
    arg_return = []
    if args.file:
        #print('file')
        arg_return.append('f')
        port_list = parse_file(args.ports)
    elif args.port:
        #print('port')
        arg_return.append('p')
        port_list.append(args.ports)
        return 'p', port_list
    elif args.range:
        #print('range')
        arg_return.append('r')
        range_l = str(sys.argv[3]).split('-')
        for i in range(int(range_l[0]),int(range_l[1])+1):
            port_list.append(i)
    else:
        return None
    if args.verbose:
        arg_return.append('v')
    if args.export:
        arg_return.append('e')
    return arg_return, port_list

commandline_results = commandline_parse()

#testing to see if 2 seperate scan functions are more effecient
def raw_port_scan(host: str, port: List[str], results_list:list):
    try:
        int(port)
    except ValueError:
        print(f"ERROR Expected integer - Received: {port}")
        print('-------------')
        return False
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(6)
    service = get_service_name(port)
    try:
        sock.connect((host,int(port)))
        if 'v' in commandline_results[0]:
            print(f'Port {port} is Open. Service: {service}')
        results_list.append((port , 'Open', service))
        sock.close()
    except socket.timeout:
        if 'v' in commandline_results[0]:
            print(f'Port {port} timed out. Service: {service}')
        results_list.append((port,'Timed Out', service))
        sock.close()
    except socket.error as e:
        if 'v' in commandline_results[0]:
            print(f'Port {port} connection error {e}. Service: {service}')
        results_list.append((port , f'Could not connect: {e}',service))
        sock.close()
        

#since threading makes the output look ugly, this exports it into a csv instead.
def export_csv(results:List[str],output_filename):
    with open(output_filename, 'w', newline='') as csvfile:
        fieldnames = ['Port ', ' Status', 'Service: ']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for port, status, service in results:
            writer.writerow({'Port ': port, ' Status': status, 'Service: ': service})

    print(f'File: {output_filename}, has been succesfully generated.')

def thread_scan(host:str,ports:List[str]):
    threads = []
    results_list = []

    for port in ports:
        port_number = int(port)

        #sets the maximum number of threads equal to 'max_threads'
        while threading.active_count() >= max_threads:
            #waits until a thread is availible to continue.
            pass

        thread = threading.Thread(target=raw_port_scan,args=(host,port_number,results_list))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    results = sorted(results_list, key=lambda x: x[0])
    return results

#if this script is the main program being run, attempt to scan ports using get_input
if __name__ == "__main__":
    result = []
    input_type = commandline_results[0]
    ports = commandline_results[1]
    if ports[0] != ports[len(ports)-1]: 
        port_range_str = '-'.join([str(ports[0]),str(ports[len(ports)-1])])
    else:
        port_range_str = ''.join(ports)
    if not host:
        print('ERROR! Invalid ip address. Check input and try again!')
    if input_type == None:
        print(f'ERROR! {"-".join(sys.argv)} is not acceptable input. Try using -h for more info.')
    else:
        print(f'Scanning port(s): {port_range_str}, on host: {host}')
        print('--------------------------')
        if 'e' in commandline_results[0]:
            start_time = time.time()
            export_csv(thread_scan(host,ports),export_filename)
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f'Scan completed in {elapsed_time:.2f} seconds.')
        elif ('v', 'e') not in commandline_results[0]:
            print("Looks like you didn't specify any output modifiers, but I'm still scannin'!")
            start_time = time.time()
            thread_scan(host, ports)
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f'Scan completed in {elapsed_time:.2f} seconds.')