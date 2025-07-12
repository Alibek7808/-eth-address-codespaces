#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAX_ACTIVE_ADDRS 2000000

char **active_addrs = NULL;
size_t active_count = 0;

void load_active_addresses(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("❌ Не удалось открыть active_eth.txt");
        exit(1);
    }

    active_addrs = malloc(MAX_ACTIVE_ADDRS * sizeof(char *));
    if (!active_addrs) {
        fprintf(stderr, "❌ Ошибка выделения памяти\n");
        exit(1);
    }

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;
        active_addrs[active_count] = strdup(line);
        active_count++;
        if (active_count >= MAX_ACTIVE_ADDRS) break;
    }

    fclose(f);
    printf("📂 Загружено %zu активных адресов\n", active_count);
}

int is_active_address(const char *addr) {
    for (size_t i = 0; i < active_count; i++) {
        if (strcasecmp(addr, active_addrs[i]) == 0)
            return 1;
    }
    return 0;
}

void keccak256(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash_out, NULL);
    EVP_MD_CTX_free(ctx);
}

void hex_from_bytes(const uint8_t *bytes, size_t len, char *out_hex) {
    for (size_t i = 0; i < len; i++)
        sprintf(&out_hex[i * 2], "%02x", bytes[i]);
    out_hex[len * 2] = '\0';
}

void process_privkey(const char *priv_hex, secp256k1_context *ctx, FILE *out_all, FILE *out_found) {
    if (strlen(priv_hex) != 64) {
        fprintf(stderr, "⛔ Неверная длина ключа: %s\n", priv_hex);
        return;
    }

    uint8_t priv[32];
    for (int i = 0; i < 32; i++) {
        if (sscanf(&priv_hex[i * 2], "%2hhx", &priv[i]) != 1) {
            fprintf(stderr, "⛔ Ошибка парсинга: %s\n", priv_hex);
            return;
        }
    }

    if (!secp256k1_ec_seckey_verify(ctx, priv)) {
        fprintf(stderr, "❌ Невалидный приватный ключ: %s\n", priv_hex);
        return;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv)) {
        fprintf(stderr, "❌ Ошибка генерации pubkey для: %s\n", priv_hex);
        return;
    }

    uint8_t pubkey_ser[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_ser, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    uint8_t hash[32];
    keccak256(pubkey_ser + 1, 64, hash);

    char eth_addr[41];
    hex_from_bytes(&hash[12], 20, eth_addr);  // 20 байт = адрес

    fprintf(out_all, "%s\n%s\n", priv_hex, eth_addr);

    if (is_active_address(eth_addr)) {
        fprintf(out_found, "%s\n%s\n", priv_hex, eth_addr);
        printf("🎯 Найден активный: %s\n", eth_addr);
    }
}

int main() {
    load_active_addresses("active_eth.txt");

    FILE *file = fopen("keys.txt", "r");
    if (!file) {
        perror("❌ Не удалось открыть keys.txt");
        return 1;
    }

    FILE *out_all = fopen("output.txt", "w");
    FILE *out_found = fopen("found.txt", "w");
    if (!out_all || !out_found) {
        perror("❌ Не удалось создать выходные файлы");
        return 1;
    }

    char line[128];
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        char clean_key[65];
        strncpy(clean_key, line, 64);
        clean_key[64] = '\0';

        process_privkey(clean_key, ctx, out_all, out_found);
    }

    secp256k1_context_destroy(ctx);
    fclose(file);
    fclose(out_all);
    fclose(out_found);

    printf("✅ Готово! Результаты в output.txt, найденные в found.txt\n");
    return 0;
}
