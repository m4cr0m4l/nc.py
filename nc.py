#!/usr/bin/env python

import argparse
import socket
import shlex
import ssl
import subprocess
import sys
import threading

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.run(shlex.split(cmd), capture_output=True, encoding='utf-8')
    return output.stdout


class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET6 if self.args.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
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
        try:
            if self.args.ssl:
                context = ssl.create_default_context()
                if not self.args.ssl_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                self.socket = context.wrap_socket(self.socket, server_hostname=self.args.target)

            self.socket.connect((self.args.target, self.args.port))
            self.print_verbose(f'[*] Connected to {self.args.target}:{self.args.port}')
            if self.buffer:
                self.socket.send(self.buffer)
                self.socket.close()
                sys.exit()

            threading.Thread(target=self.handle_user_input, daemon=True).start()

            while True:
                response = self.socket.recv(4096)
                if not response:
                    self.print_verbose('[*] Connection closed by the server.')
                    return
                sys.stdout.buffer.write(response)
                sys.stdout.flush()

        except KeyboardInterrupt:
            self.print_verbose('[!] User terminated.')
        except ssl.SSLError as e:
            print(f'[!] SSL error: {e}', file=sys.stderr)
        except socket.error as e:
            print(f'[!] Socket error: {e}', file=sys.stderr)
        except Exception as e:
            print(f'[!] An unexpected error occurred: {e}', file=sys.stderr)
        finally:
            self.socket.close()
            sys.exit()

    def handle_user_input(self):
        while True:
            user_input = input() + '\n'
            self.socket.send(user_input.encode())

    def listen(self):
        try:
            if self.args.ssl:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(self.args.ssl_cert, self.args.ssl_key)

            self.socket.bind((self.args.target, self.args.port))
            self.socket.listen(5)
            self.print_verbose(f'[*] Listening on {self.args.target}:{self.args.port}')

            while True:
                try:
                    client_socket, address = self.socket.accept()
                    self.print_verbose(f'[*] Accepted connection from {address[0]}:{address[1]}')
                    if self.args.ssl:
                        client_socket = context.wrap_socket(client_socket, server_side=True)
                    client_thread = threading.Thread(target=self.handle, args=(client_socket,), daemon=True)
                    client_thread.start()

                except ssl.SSLError as e:
                    print(f'[!] SSL error: {e}', file=sys.stderr)
                    continue
                except socket.error as e:
                    print(f'[!] Socket error: {e}', file=sys.stderr)
                    continue

        except KeyboardInterrupt:
            self.print_verbose('[!] User terminated.')
        except Exception as e:
            print(f'[!] An unexpected error occurred: {e}', file=sys.stderr)
        finally:
            self.socket.close()
            sys.exit()

    def handle(self, client_socket):
        try:
            if self.args.exec:
                output = execute(self.args.exec)
                client_socket.send(output.encode())

            elif self.args.command:
                cmd_buffer = b''
                while True:
                    client_socket.send(b'#> ')
                    while b'\n' not in cmd_buffer:
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''

            while True:
                data = client_socket.recv(64)
                if not data:
                    self.print_verbose('[*] Client disconnected.')
                    break
                print(data.decode(), end='')

        except Exception as e:
            self.print_verbose(f'[!] Error in handling client: {e}')
        finally:
            client_socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python Netcat')
    parser.add_argument('target', nargs='?', default='127.0.0.1', help='specified IP')
    parser.add_argument('port', type=int, nargs='?', default='8888', help='specified port')
    parser.add_argument('-6', '--ipv6', action='store_true', help='use IPv6')
    parser.add_argument('-c', '--command', action='store_true', help='initialize command shell')
    parser.add_argument('-e', '--exec', help='execute specified command')
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
        if not sys.stdin.isatty():
            buffer = sys.stdin.buffer.read()
        else:
            buffer = ''

    nc = NetCat(args, buffer)
    nc.run()
