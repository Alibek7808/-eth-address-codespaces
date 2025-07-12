#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "btc/bip32.h"
#include <secp256k1.h>
#include <openssl/evp.h>

void keccak256(const uint8_t *data, size_t len, uint8_t *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <seed_hex>\n", argv[0]);
        return 1;
    }

    // 1. Seed hex → bytes
    uint8_t seed[64];
    for (int i = 0; i < 64; i++) seed[i] = 0;
    if (strlen(argv[1]) != 128) {
        printf("Error: seed hex must be 128 hex chars (64 bytes)\n");
        return 1;
    }
    for (int i = 0; i < 64; i++)
        sscanf(&argv[1][2*i], "%2hhx", &seed[i]);

    // 2. BIP32 root key
    HD_WALLET wallet = hd_wallet_from_seed(seed, 1024);
    HDNode node = wallet.root;

    // 3. Derive path: 44'/60'/0'/0/0
    hd_node_private_ckd_prime(&node, 44);
    hd_node_private_ckd_prime(&node, 60);
    hd_node_private_ckd_prime(&node, 0);
    hd_node_private_ckd(&node, 0);
    hd_node_private_ckd(&node, 0);

    // 4. Extract privkey
    uint8_t priv[32];
    memcpy(priv, node.private_key, 32);

    // 5. Generate pubkey and address
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pub;
    secp256k1_ec_pubkey_create(ctx, &pub, priv);
    uint8_t ser[65]; size_t sz = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser, &sz, &pub, SECP256K1_EC_UNCOMPRESSED);
    uint8_t hash[32];
    keccak256(ser + 1, 64, hash);
    printf("0x");
    for (int i = 12; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    secp256k1_context_destroy(ctx);
    return 0;
}
