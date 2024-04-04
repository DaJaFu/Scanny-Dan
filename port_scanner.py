#!/usr/bin/env python3
import sys
import datetime
import socket
import csv
import argparse
import threading
import os
import logging
#import winsound
from typing import List
print('+------Scanny-Dans-Port-Scanner------+')

logging.basicConfig(filename='port_scanner.log')
log_header = f'[{datetime.datetime.now()}]{logging.getLevelName(logging.INFO)}'

#path to sound files
sounds_path = os.path.join(os.getcwd(),'sounds')

class port_scanner:
    def __init__(self,max_threads):
        self.max_threads = max_threads
        self.results_list = []
        self.cmd = self.commandline_parse() 

    def main(self):
        self.thread_scan(self.cmd[0],self.cmd[1])
        if self.args.export:
            self.export_csv(self.results_list, "port_scan"+str(datetime.datetime.now())+".csv")


    def abort(self,ex):
        print(f'Error: {ex}')
        print('Exiting...')
        sys.exit()

    #gathers ip address from command line input, validates, and converts from hostname
    def validate_host(self,host:str)->str:
        #log info: "Attempting to validate host..."
        try:
            socket.inet_aton(host)
            return host
        except socket.error:
            #log info: "Input is hostname, attempting to get Ipv4 address..."
            try:
                socket.gethostbyname(host)
                return host
            except:
                #log error: "Input was neither hostname nor valid ipv4 address... Exiting"
                self.abort("Could not validate host.")
        return None
    
    #open a file specified in the command line and search for valid port numbers
    def parse_file(self, filename)->List[str]:
        with open(filename,'r') as file:
            port_list = []
            current_port = ''
            read_file = file.read()
            for i in read_file:
                try:
                    ii = int(i)
                    if len(current_port) < 5 and (int(current_port)+ii)<=65535:
                        current_port += i
                    else:
                        port_list.append(current_port)
                        current_port = i
                except:
                    port_list.append(current_port)
                    current_port = ''
                    continue
            return port_list

    #get input type, ports, and other output modifiers from command line
    def commandline_parse(self):
        parser = argparse.ArgumentParser(
            prog = 'Dans Port Scanner',
            description='Dannys port scanner, try looking at the readme for more info.',
            epilog = 'Thanks for checking it out!')
        parser.add_argument('hostname',help='Hostname to scan.')
        parser.add_argument('ports',nargs='?',help='Port(s) to be scanned.',default=22)
        parser.add_argument('-f', '--file',action='store_true', help='Takes input from a given file.')
        parser.add_argument('-v', '--verbose',default=False,action='store_true',help='Prints all info to console.')
        parser.add_argument('-e','--export',default=False,action='store_true',help='Exports output to csv.')
        parser.add_argument('-o','--open',default=False,action='store_true',help='Show only open ports.')
        self.args = parser.parse_args()
        #print(self.args)
        #print(f"Args: Host={self.args.hostname}, Ports = {self.args.ports}")
        host = self.validate_host(self.args.hostname)
        if self.args.file:
            ports = self.parse_file(self.args.ports)
        else:
            if '-' in self.args.ports:
                port_endpoints = self.args.ports.split('-')
                ports = []
                for i in range(int(port_endpoints[0]),int(port_endpoints[1])):
                    ports.append(i)
            else:
                ports = [self.args.ports]
        return [host,ports]

    #testing to see if 2 seperate scan functions are more effecient
    def port_scan(self, host: str,port:int,verbose:bool):
        #try to add banner grabbing if port is open, and expected service if closed.
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            port = int(port)
        except ValueError:
            #log warning: "Port not a valid integer"
            pass
        try:
            sock.connect((host,port))
            status = " Open"
            #log info "connected to port: {port}"
        except:
            status = " Closed"
            #log info "could not connect to port"
        if verbose:
            print("-"*20+f"\nHost: {host} \nPort: {str(port)} \nStatus:{status}\n"+"-"*20+"\n")
        self.results_list.append((port,status))
        return (port,status)
        
    #since threading makes the output look ugly, this exports it into a csv instead.
    def export_csv(self, results:List[str],output_filename):
        with open(output_filename, 'w', newline='') as csvfile:
            fieldnames = ['Port ', ' Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for port, status in results:
                writer.writerow({'Port ': port, ' Status': status})
        print(f'File: {output_filename}, has been succesfully generated.')

    def thread_scan(self, host:str,ports:List[str]):
        threads = []
        for port in ports:
            port_number = int(port)
            #sets the maximum number of threads equal to 'max_threads'
            while threading.active_count() >= self.max_threads:
                #waits until a thread is availible to continue.
                pass

            thread = threading.Thread(target=self.port_scan,args=(host,port_number,self.args.verbose))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()

if __name__ == "__main__":
    instance = port_scanner(50)
    instance.main()
        