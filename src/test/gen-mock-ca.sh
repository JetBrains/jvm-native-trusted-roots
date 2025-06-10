#!/bin/bash

set -e -x -u -o pipefail

root="$(cd "$(dirname "$0")"; pwd)"
dir="$root/resources/mock-ca"

rm -rf "$dir"
mkdir -p "$dir"
cd "$dir"

cp "$root/mock-ca.cnf" openssl.cnf

openssl genrsa -out root.key 2048
openssl req -x509 -sha256 -nodes -extensions v3_ca -key root.key \
  -subj "/O=JETBRAINS/CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA" -days 10950 -out root.crt
openssl x509 -inform PEM -in root.crt -outform DER -out root.cer

openssl genrsa -out intermediate.key 2048
openssl req -new -sha256 -nodes -key intermediate.key  \
  -subj "/O=JETBRAINS/CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-INTERMEDIATE-CA" -out test-intermediate-ca.csr

openssl x509 -req \
 -extensions v3_ca \
 -extfile openssl.cnf \
 -in test-intermediate-ca.csr \
 -CA root.crt \
 -CAkey root.key \
 -CAcreateserial \
 -out intermediate-ca.pem \
 -days 10950 \
 -sha256

openssl genrsa -out client.key 2048
openssl req -new -sha256 -nodes -key client.key  \
  -subj "/O=JETBRAINS/CN=JVM-CLIENT-CERT" -out test-client.csr

openssl x509 -req \
 -extensions my_client \
 -extfile openssl.cnf \
 -in test-client.csr \
 -CA root.crt \
 -CAkey root.key \
 -CAcreateserial \
 -out client.pem \
 -days 100 \
 -sha256

rm -f root.key root.srl test-intermediate-ca.csr intermediate.key client.key test-client.csr
