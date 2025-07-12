#!/bin/bash
set -e

echo "📥 Cloning libsecp256k1..."
git clone https://github.com/bitcoin-core/secp256k1 || true

cd secp256k1
./autogen.sh
./configure --enable-module-ecdh --enable-experimental
make
cd ..

echo "🔧 Compiling eth_address..."
gcc main.c -o eth_address \
  -Isecp256k1/include \
  secp256k1/.libs/libsecp256k1.a \
  -lcrypto

echo "✅ Done! Run with ./eth_address"
