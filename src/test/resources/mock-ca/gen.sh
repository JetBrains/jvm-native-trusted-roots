#!/bin/bash

set -e -x -u -o pipefail

## Generate Root CA
openssl genrsa -out root.key 2048
openssl req -x509 -sha256 -nodes -extensions v3_ca -key root.key \
  -subj "/O=JETBRAINS/CN=JVM-NATIVE-TRUSTED-ROOTS-MOCK-CA" -days 10950 -out root.crt
openssl x509 -inform PEM -in root.crt -outform DER -out root.cer

## Generate Intermediate CA
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

## Generate leaf from Intermediate CA

openssl genrsa -out leaf-from-intermediate.key 2048
openssl req -new \
  -sha256 \
  -nodes \
  -key leaf-from-intermediate.key \
  -subj "/O=JETBRAINS/CN=LEAF-FROM-INTERMEDIATE" \
  -out leaf-from-intermediate.csr
openssl x509 -req \
 -in leaf-from-intermediate.csr \
 -CA intermediate-ca.pem \
 -CAkey intermediate.key \
 -CAcreateserial \
 -out leaf-from-intermediate.crt \
 -days 10950 \
 -extfile openssl.cnf \
 -sha256

## Generate leaf from Root CA

openssl genrsa -out leaf-from-root.key 2048
openssl req -new \
  -sha256 \
  -nodes \
  -key leaf-from-root.key \
  -subj "/O=JETBRAINS/CN=LEAF-FROM-INTERMEDIATE" \
  -out leaf-from-root.csr
openssl x509 -req \
 -in leaf-from-root.csr \
 -CA root.crt \
 -CAkey root.key \
 -CAcreateserial \
 -out leaf-from-root.crt \
 -days 10950 \
 -extfile openssl.cnf \
 -sha256

## Cleanup
rm -f ./*.key ./*.csr ./*.srl
