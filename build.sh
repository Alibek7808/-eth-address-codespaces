#!/bin/bash
set -e

echo "📦 Cloning libbtc..."
if [ ! -d libbtc ]; then
  git clone https://github.com/libbtc/libbtc
fi
cd libbtc
./autogen.sh || true
./configure --enable-bip32 --enable-sha3
make
cd ..

echo "🔧 Cloning secp256k1..."
if [ ! -d secp256k1 ]; then
  git clone https://github.com/bitcoin-core/secp256k1
fi
cd secp256k1
./autogen.sh
./configure --enable-module-ecdh --enable-experimental
make
cd ..

echo "🚀 Compiling eth_from_seed..."
gcc main.c -o eth_from_seed \
  -Ilibbtc/include -Isecp256k1/include \
  libbtc/src/libbtc.a secp256k1/.libs/libsecp256k1.a \
  -lcrypto

echo "✅ Build complete. Run with: ./eth_from_seed <seed_hex>"
