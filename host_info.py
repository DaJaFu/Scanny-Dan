import socket
import re

'''
Validate and Gather host info. This is accomplished by first checking to make sure
that IP address is a proper 32 bit IPv4 address. After that, the first octet is examined
to see what address class the IP is. Then using sockets "gethostbyaddr" check to see
if there is a related hostname. If the validation process fails it will then check
to see if the input was a hostname and if it is tries again after converting.
'''

def validate_ip(ip:str):
    ipv4_pattern = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
    clas = {240:'E',224:'D',192:'C',128:'B',0:'A'}
    out = {"Address":None,"Hostname":None,"Class":None}
    while True:
        if re.match(ipv4_pattern,ip):
            try:
                out["Hostname"] = socket.gethostbyaddr(ip)
            except Exception as e:
                print(f"ERROR: Could not find address hostname: {e}")
            out["Address"] = ip
            first = ip.split('.')[0]
            break
        else:
            try:
                ip = socket.gethostbyname(ip)    
            except:
                print(f"ERROR! {ip} is not a valid IPv4 address or hostname.")
                return None
    for i in clas:
        if int(first) >= int(i):
            out["Class"] = clas.get(i)
    return out

if __name__ == "__main__":
    print(validate_ip(input("Enter a valid ip address: ")))