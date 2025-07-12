#!/bin/bash
set -e

# 1. Clone libbtc
if [ ! -d libbtc ]; then
  git clone https://github.com/libbtc/libbtc
fi
cd libbtc
./autogen.sh || true
./configure --enable-bip32 --enable-sha3
make
cd ..

# 2. Clone secp256k1
if [ ! -d secp256k1 ]; then
  git clone https://github.com/bitcoin-core/secp256k1
fi
cd secp256k1
./autogen.sh
./configure --enable-module-ecdh --enable-experimental
make
cd ..

# 3. Build main.c
gcc main.c -o eth_from_seed \
  -Ilibbtc/include -Isecp256k1/include \
  libbtc/src/libbtc.a secp256k1/.libs/libsecp256k1.a \
  -lcrypto

echo "Built eth_from_seed; run ./eth_from_seed <seed_hex>"
