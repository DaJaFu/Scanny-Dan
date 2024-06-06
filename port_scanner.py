#!/usr/bin/env python3
import datetime
import csv
import threading
import os
import logging
from scapy.all import *
from typing import List

'''
Get input from command line via scanner argparse, use input
'''


#validate_ip(ip:str):
from host_info import validate_ip

#cmd_in is all relevant input from the commandline
from scanner_argparse import input_parser
cmd_in = input_parser.commandline_parse(input_parser)
#host & ports should be self explanatory. host is a str, and ports is List[str]
host = cmd_in[0]
ports = cmd_in[1]
#args is a namespace object where all contents are accessible by entering the variable name (i.e, args.open)
args = cmd_in[2]

logging.basicConfig(filename='port_scanner.log')
log_header = f'[{datetime.now()}]{logging.getLevelName(logging.INFO)}'

#path to sound files
sounds_path = os.path.join(os.getcwd(),'sounds')

class port_scanner:
    def __init__(self):
        self.results_list = []
        self.host = validate_ip(host)['Address']
        self.max_threads = 50

    #attempts TCP handshake with given ip:port
    def tcp_handshake(self, port, ip):
        packet=IP(dst=ip)/TCP(dport=int(port),flags='S')
        #sends packet to destination ip address and stores anything received
        response = sr1(packet, timeout=2)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
            #print(f"Received SYN-ACK from address {ip} over port {port}")
            ack_packet = IP(dst=ip)/TCP(dport=int(port),flags='A')
            send(ack_packet)
            self.results_list.append((port,"Open"))
            return (port, True)
        else:
            self.results_list.append((port,"Closed"))
            return (port, False)

    #since threading makes the output look ugly, this exports it into a csv instead.
    def export_csv(self, results, output_filename):
        with open(output_filename, 'w', newline='') as csvfile:
            fieldnames = ['Port ', ' Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for port, status in results:
                writer.writerow({'Port ': port, ' Status': status})
        print(f'File: {output_filename}, has been succesfully generated.')


    def thread_scan(self,host:str,ports:List[str]):
        threads = []
        for port in ports:
            port_number = int(port)
            #sets the maximum number of threads equal to 'max_threads'
            while threading.active_count() >= self.max_threads:
                #waits until a thread is availible to continue.
                pass

            thread = threading.Thread(target=self.tcp_handshake,args=(port_number,host))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()

    def run(self):
        self.thread_scan(host,ports)
        if args.verbose:
            for i in self.results_list:
                print(f'Port: {i[0]} is {i[1]}')
        if args.export:
            print(True)
            self.export_csv(self.results_list, "test.csv")
        
if __name__ == "__main__":
    scanner = port_scanner()
    port_scanner.run(scanner)
    print(args)