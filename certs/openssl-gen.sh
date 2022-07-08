#!/bin/bash
set -ex
# Generate CA Key
openssl genrsa -aes256 -passout pass:1 -out ca.key.pem 4096
openssl rsa -passin pass:1 -in ca.key.pem -out ca.key.pem.tmp
mv ca.key.pem.tmp ca.key.pem

# Generate CA Pem
openssl req -config openssl.cnf -key ca.key.pem -new -x509 -days 7300 -subj /C=US/ST=IL/L=Chicago/O=HackEmby/OU=HackEmby/CN=HackEmby/emailAddress=HackEmby@gmail.com -sha256 -extensions v3_ca -out ca.pem

# Generate CA CRT For Windows User
openssl x509 -in ca.pem -out ca.crt
