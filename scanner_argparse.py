import argparse
from typing import List
import socket

'''
Parse command line input, do any processing to get a port list, and then output
port list, ip, and flags.
'''

class input_parser:
    #open a file specified in the command line and search for valid port numbers
    def parse_file(self, filename)->List[str]:
        with open(filename,'r') as file:
            port_list = []
            current_port = ''
            read_file = file.read()
            for i in read_file:
                try:
                    i = int(i)
                    if len(current_port) < 5 and (int(current_port)+i)<=65535:
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
        parser.add_argument('ports',nargs='?',help='Port(s) to be scanned, or filename containing ports.',default=22)
        parser.add_argument('-f', '--file',action='store_true', help='Takes input from a given file.')
        parser.add_argument('-v', '--verbose',default=False,action='store_true',help='Prints all info to console.')
        parser.add_argument('-e','--export',default=False,action='store_true',help='Exports output to csv.')
        parser.add_argument('-o','--open',default=False,action='store_true',help='Show only open ports.')
        args = parser.parse_args()
        #print(self.args)
        #print(f"Args: Host={self.args.hostname}, Ports = {self.args.ports}")
        host = args.hostname
        if args.file:
            ports = self.parse_file(args.ports)
        else:
            if '-' in args.ports:
                port_endpoints = args.ports.split('-')
                ports = []
                for i in range(int(port_endpoints[0]),int(port_endpoints[1])+1):
                    ports.append(i)
            else:
                ports = [args.ports]
        return [host,ports,args]
            
if __name__ == "__main__":
    parser = input_parser
    print(parser.commandline_parse(parser))