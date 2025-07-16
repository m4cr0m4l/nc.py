#!/usr/bin/env python

import argparse
import select
import socket
import shlex
import ssl
import subprocess
import sys
import textwrap
import threading

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()


class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def print_verbose(self, message):
        if self.args.verbose:
            print(message, file=sys.stderr)

    def send(self):
        if self.args.ssl:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if not self.args.ssl_verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.socket = context.wrap_socket(self.socket, server_hostname=self.args.target)

        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response, end='')
                    buffer = input()
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            self.print_verbose('[!] User terminated.')
            self.socket.close()
            sys.exit()

    def listen(self):
        if self.args.ssl:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.args.ssl_cert, self.args.ssl_key)

        self.print_verbose(f'[*] Listening on {self.args.target}:{self.args.port}')
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        try:
            while True:
                client_socket, address = self.socket.accept()
                self.print_verbose(f'[*] Accepted connection from {address[0]}:{address[1]}')
                if self.args.ssl:
                    client_socket = context.wrap_socket(client_socket, server_side=True)
                client_thread = threading.Thread(target=self.handle, args=(client_socket,))
                client_thread.start()
        except KeyboardInterrupt:
            self.print_verbose('[!] User terminated.')
            self.socket.close()
            sys.exit()

    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'#> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Python Netcat',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
          nc.py -l -c 192.168.1.108 5555 # command shell
          nc.py -l 192.168.1.108 5555 > file # upload to file
          nc.py -l -e=\"cat /etc/passwd\" 192.168.1.108 5555 # execute command
          echo 'ABCDEFGHI' | ./nc.py 192.168.1.108 135 # echo local text to server port 135
          nc.py 192.168.1.108 5555 # connect to server
          '''))
    parser.add_argument('target', help='specified IP')
    parser.add_argument('port', type=int, help='specified port')
    parser.add_argument('-c', '--command', action='store_true', help='initialize command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-v', '--verbose', action='store_true', help='be verbose')
    parser.add_argument('-s', '--ssl', action='store_true', help='enable SSL')
    parser.add_argument('--ssl-cert', default='server.crt', help='specify SSL certificate file')
    parser.add_argument('--ssl-key', default='server.key', help='specify SSL private key')
    parser.add_argument('--ssl-verify', action='store_true', help='verify SSL certificates')
    args = parser.parse_args()
    if args.listen:
        buffer = ''
    else:
        if select.select([sys.stdin], [], [], 0)[0]:
            buffer = sys.stdin.read()
        else:
            buffer = ''

    nc = NetCat(args, buffer.encode('utf-8'))
    nc.run()
