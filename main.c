#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "btc/bip32.h"
#include <secp256k1.h>
#include <openssl/evp.h>

// Keccak256 (Ethereum)
void keccak256(const uint8_t *data, size_t len, uint8_t *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <seed_hex_64_bytes>\n", argv[0]);
        return 1;
    }

    uint8_t seed[64];
    if (strlen(argv[1]) != 128) {
        printf("❌ Error: seed must be 128 hex chars (64 bytes)\n");
        return 1;
    }

    for (int i = 0; i < 64; i++)
        sscanf(&argv[1][i*2], "%2hhx", &seed[i]);

    HDNode node;
    hd_node_from_seed(seed, 64, SECP256K1_KEY, &node);

    // Derive m/44'/60'/0'/0/0
    hd_node_private_ckd_prime(&node, 44);
    hd_node_private_ckd_prime(&node, 60);
    hd_node_private_ckd_prime(&node, 0);
    hd_node_private_ckd(&node, 0);
    hd_node_private_ckd(&node, 0);

    // Init secp256k1 + generate pubkey
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, node.private_key);

    uint8_t ser_pub[65]; size_t pub_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser_pub, &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    uint8_t hash[32];
    keccak256(ser_pub + 1, 64, hash); // skip 0x04 prefix

    printf("✅ Ethereum address: 0x");
    for (int i = 12; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    secp256k1_context_destroy(ctx);
    return 0;
}
