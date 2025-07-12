#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

void keccak256(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash_out, NULL);
    EVP_MD_CTX_free(ctx);
}

int main() {
    const char *priv_hex = "f8544583fd385afa336bd2a47c0aebb759077690803ad28ca277c83056c5e72c";
    uint8_t priv[32];
    for (int i = 0; i < 32; i++)
        sscanf(&priv_hex[i * 2], "%2hhx", &priv[i]);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv)) {
        printf("❌ Ошибка генерации pubkey\n");
        return 1;
    }

    uint8_t pubkey_ser[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_ser, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    uint8_t hash[32];
    keccak256(pubkey_ser + 1, 64, hash);  // исключаем первый байт 0x04

    printf("✅ Ethereum address: 0x");
    for (int i = 12; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");

    secp256k1_context_destroy(ctx);
    return 0;
}
