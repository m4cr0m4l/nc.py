#!/usr/bin/env python

import argparse
import datetime
import os
import socket
import ssl
import subprocess
import sys
import threading

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    from cryptography import x509
except ImportError:
    pass

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    try:
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if output.returncode != 0:
            return output.stderr
        return output.stdout
    except Exception as e:
        return f'Error executing command: {e}'

def generate_ssl_files(ssl_cert = 'server.crt', 
                  ssl_key = 'server.key',
                  country = 'AU',
                  state = '',
                  locality = '',
                  organization = '',
                  common_name = 'localhost',
                  valid_days = 365):

    key = ed25519.Ed25519PrivateKey.generate()
    with open(ssl_key, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, algorithm=None)
    )
    with open(ssl_cert, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


class NetCat:
    def __init__(self, args):
        self.args = args
        self.socket = self.create_socket()
        self.clients = []
        self.lock = threading.Lock()
        self.exit_event = threading.Event()

    def create_socket(self):
        address_family = socket.AF_INET6 if self.args.ipv6 else socket.AF_INET
        new_socket = socket.socket(address_family, socket.SOCK_STREAM)
        new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return new_socket

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

            # Send standard input
            if not sys.stdin.isatty():
                while True:
                    data = sys.stdin.buffer.read(8192)
                    if not data:
                        break
                    self.socket.send(data)
                # drain any TLS close/alert from the peer
                if args.ssl:
                    try:
                        self.socket.settimeout(0.1)
                        self.socket.recv(4096)
                    except TimeoutError:
                        pass
                return

            threading.Thread(target=self.receive_data, daemon=True).start()
            threading.Thread(target=self.handle_user_input, daemon=True).start()
            self.exit_event.wait()

        except ssl.SSLError as e:
            print(f'[!] SSL error: {e}', file=sys.stderr)
        except socket.error as e:
            print(f'[!] Socket error: {e}', file=sys.stderr)
        except KeyboardInterrupt:
            self.print_verbose('[!] User terminated.')
        except Exception as e:
            print(f'[!] An unexpected error occurred: {e}', file=sys.stderr)
        finally:
            self.socket.close()

    def receive_data(self):
        try:
            while True:
                response = self.socket.recv(4096)
                if not response:
                    self.print_verbose('[*] Connection closed by the server.')
                    self.exit_event.set()
                    return
                sys.stdout.buffer.write(response)
                sys.stdout.flush()

        except socket.error as e:
            print(f'[!] Socket error: {e}', file=sys.stderr)
        finally:
            self.exit_event.set()

    def handle_user_input(self):
        try:
            while True:
                user_input = input() + '\n'
                self.socket.send(user_input.encode())
        except EOFError:
            pass
        finally:
            self.exit_event.set()

    def check_ssl_files(self, cert, key):
        cert_isfile = os.path.isfile(cert)
        cert_readable = os.access(cert, os.R_OK)
        key_isfile = os.path.isfile(key)
        key_readable = os.access(key, os.R_OK)

        if not cert_isfile and key_isfile:
            print('[!] SSL certificate file is missing, but key file is present.', file=sys.stderr)
            sys.exit(1)
        if cert_isfile and not key_isfile:
            print('[!] SSL private key is missing, but certificate is present', file=sys.stderr)
            sys.exit(1)
        if cert_isfile and not cert_readable:
            print('[!] SSL certificate file: access denied.', file=sys.stderr)
            sys.exit(1)
        if key_isfile and not key_readable:
            print('[!] SSL private key: access denied.', file=sys.stderr)
            sys.exit(1)
        if cert_isfile and key_isfile:
            return

        if 'cryptography' not in sys.modules:
            print("[!] Install the cryptography package or provide certificate and key files.", file=sys.stderr)
            sys.exit(1)

        try:
            generate_ssl_files(cert, key)
        except Exception as e:
            print(f"[!] Failed to generate certificate and key files: {e}", file=sys.stderr)
            sys.exit(1)

    def listen(self):
        try:
            if self.args.ssl:
                self.check_ssl_files(self.args.ssl_cert, self.args.ssl_key)
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

                    if not self.args.exec and not self.args.command:
                        with self.lock:
                            self.clients.append(client_socket)
                        threading.Thread(target=self.handle_server_input, daemon=True).start()

                    threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()


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

    def handle_client(self, client_socket):
        try:
            if self.args.exec:
                output = execute(self.args.exec)
                client_socket.send(output.encode())

            elif self.args.command:
                cmd_buffer = b''
                while True:
                    client_socket.send(b'#> ')
                    while b'\n' not in cmd_buffer:
                        data = client_socket.recv(64)
                        if not data:
                            self.print_verbose('[*] Client disconnected.')
                            return
                        cmd_buffer += data
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''

            else:
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        self.print_verbose('[*] Client disconnected.')
                        with self.lock:
                            self.clients.remove(client_socket)
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()

        except Exception as e:
            self.print_verbose(f'[!] Error in handling client: {e}')
        finally:
            client_socket.close()

    def handle_server_input(self):
        try:
            while True:
                server_input = input() + '\n'
                self.send_to_all_clients(server_input.encode())
        except EOFError:
            pass

    def send_to_all_clients(self, data):
        for client in self.clients:
            client.send(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python Netcat')
    parser.add_argument('target', nargs='?', default='127.0.0.1', help='specified IP')
    parser.add_argument('port', type=int, nargs='?', default='8888', help='specified port')
    parser.add_argument('-6', '--ipv6', action='store_true', help='use IPv6')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-c', '--command', action='store_true', help='initialize command shell')
    group.add_argument('-e', '--exec', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-v', '--verbose', action='store_true', help='be verbose')
    parser.add_argument('-s', '--ssl', action='store_true', help='enable SSL')
    parser.add_argument('--ssl-cert', 
                        default=os.environ.get('NCPY_SSL_CERT', 'server.crt'), 
                        help='specify SSL certificate file')
    parser.add_argument('--ssl-key', 
                        default=os.environ.get('NCPY_SSL_KEY', 'server.key'), 
                        help='specify SSL private key')
    parser.add_argument('--ssl-verify', action='store_true', help='verify SSL certificates')
    args = parser.parse_args()

    if args.ssl:
        args.ssl_cert = os.path.expanduser(args.ssl_cert)
        args.ssl_key = os.path.expanduser(args.ssl_key)

    if args.ipv6 and args.target == '127.0.0.1':
        args.target = '::1'

    nc = NetCat(args)
    nc.run()
