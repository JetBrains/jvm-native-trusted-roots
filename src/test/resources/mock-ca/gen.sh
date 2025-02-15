#!/bin/bash

set -e -x -u -o pipefail

openssl genrsa -out root.key 2048
openssl req -x509 -sha256 -nodes -extensions v3_ca -key root.key \
  -subj "/O=JETBRAINS/CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA" -days 10950 -out root.crt
rm -f root.key
openssl x509 -inform PEM -in root.crt -outform DER -out root.cer
