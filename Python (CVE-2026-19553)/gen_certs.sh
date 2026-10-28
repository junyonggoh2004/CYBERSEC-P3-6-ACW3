#!/bin/bash
set -e

# On Git Bash / MSYS (Windows), paths starting with "/" get silently
# rewritten to Windows paths, which breaks openssl's -subj argument.
# This disables that rewriting for this script only.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

cd "$(dirname "$0")"
mkdir -p certs
cd certs

echo "Generating CA..."
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=Demo CA"

echo "Generating attacker (evil.local) cert request..."
openssl req -newkey rsa:2048 -nodes -keyout evil.key -out evil.csr \
  -subj "/CN=evil.local"

echo "Signing attacker cert with the CA..."
# Use a real temp file instead of process substitution (<(...)) — some
# openssl builds (notably native Windows builds run from Git Bash) can't
# read bash's /dev/fd/N process-substitution pseudo-files.
printf "subjectAltName=DNS:evil.local\n" > evil_ext.cnf
openssl x509 -req -in evil.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out evil.crt -days 3650 \
  -extfile evil_ext.cnf
rm -f evil_ext.cnf

echo
echo "Certs generated successfully:"
ls -la
