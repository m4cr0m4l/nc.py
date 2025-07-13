#!/bin/sh

KEY_FILE="server.key"
CERT_FILE="server.crt"

openssl genpkey -algorithm ED25519 -out "$KEY_FILE"
openssl req -new -x509 -days 365 -key "$KEY_FILE" -out "$CERT_FILE"
