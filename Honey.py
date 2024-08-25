import sys
import argparse
from socket import socket, AF_INET, SOCK_STREAM

VERSION = '0.1a'
welcome = b"Ubuntu 18.04.1 LTS\nserver login: "

def send_email(src_address):
    pass

def honeypot(address,port=23):
    try:
        ski=socket(AF_INET,SOCK_STREAM)
        ski.bind((address, port))
        ski.listen()
        conn,addr = ski.accept()
        print('honeypot has been visited by ' + addr[0])
        send_email(addr[0])
        conn.sendall(welcome)
        while True:
            data=conn.recv(1024)
            print(data)
            if data == b'\r\n':
                ski.close()
                sys.exit()
    except: 
        ski.close()
        sys.exit()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='honeypot prototype', epilog='Version: ' + str(VERSION))
    parser.add_argument('-a','--address',help='server ip address to use',action='store', required=True)   
    args = parser.parse_args()
    
    honeypot(args.address)        