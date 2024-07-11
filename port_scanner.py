#!/usr/bin/env python3
import datetime
import csv
import threading
import os
import logging
from scapy.all import *
from typing import List

#import local files
from TCP_scan import tcp_handshake
from scanner_argparse import input_parser

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
        self.host = validate_ip(host)['Address']
        self.max_threads = 50
        self.verbose = 0
        if args.Verbose:
            self.verbose = 1

        if args.ack:
            self.scantype = True
        else:
            self.scantype = False

    #since threading makes the output look ugly, this exports it into a csv instead.
    def export_csv(self, results, output_filename):
        with open(output_filename, 'w', newline='') as csvfile:
            fieldnames = ['Port ', ' Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for i in results:
                if args.open and i["status"]!="closed":
                    writer.writerow({'Port ': i["port"], ' Status': i["status"]})
                else:
                    writer.writerow({'Port ': i["port"], ' Status': i["status"]})
        print(f'File: {output_filename}, has been succesfully generated.')

    #use threading to scan multiple ports at a time, if a TCP handshake fails, attempts UDP scan.
    def thread_scan(self,host:str,ports:List[str]):
        threads = []
        results = []
        for port in ports:
            try:
                port_number = int(port)
            except:
                print(f"ERROR: {port} is not a valid port number.")
                continue
            #sets the maximum number of threads equal to 'max_threads'
            while threading.active_count() >= self.max_threads:
                #waits until a thread is availible to continue.
                pass

            thread = threading.Thread(target=tcp_handshake,args=(port_number, host, results, self.scantype, self.verbose))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        return results

    def run(self):
        output = self.thread_scan(host,ports)
        if args.verbose or args.Verbose:
            #print(f'verbose: {args.verbose}. Verbose: {args.Verbose}. Type = {self.verbose}')
            if args.ack:
                for i in output:
                    print(f"Port: {i["port"]}, Filtered: {i["filtered"]}")
            else:
                for i in output:
                    print(f'Port: {i["port"]} , Status: {i["status"]}')
        if args.export:
            #print(True)
            self.export_csv(output, "test.csv")
        
if __name__ == "__main__":
    scanner = port_scanner()
    port_scanner.run(scanner)
    #print(args)