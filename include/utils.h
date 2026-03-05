#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <numeric>
#include <vector>

#include <pbc/pbc.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static constexpr int MESSAGE_SPACE = 32; // n1
static constexpr int ID_SPACE      = 32;
static constexpr int Zp_SPACE      = 32; // n2
static constexpr int n12           = MESSAGE_SPACE + Zp_SPACE;


struct MasterSecretKey
{
    element_t s1;
    element_t s2;
};

struct DecryptionKey
{
    element_t dk1;
    element_t dk2;
};

struct Ciphertext
{
    element_t C1;
    element_t C2;
    element_t C3;
    uint8_t   C4[n12];
};

struct Trapdoor1 { element_t td1; }; // G1
struct Trapdoor2 { element_t td2; }; // Zr

struct Trapdoor3i { element_t td3; }; // Zr
struct Trapdoor3j { element_t td3; }; // G1

struct Trapdoor4
{
    element_t TD1; // Zr
    element_t TD2; // G1
};

inline void SHA256_hash(const uint8_t *src, size_t slen, uint8_t *dest)
{
    const EVP_MD *md = EVP_sha3_256();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int dlen = SHA256_DIGEST_LENGTH;
    if (!ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1
             || EVP_DigestUpdate(ctx, src, slen) != 1
             || EVP_DigestFinal_ex(ctx, dest, &dlen) != 1)
    {
        std::cerr << "SHA256_hash failed" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ctx);
}

inline void SHA512_hash(const uint8_t *src, size_t slen, uint8_t *dest)
{
    const EVP_MD *md = EVP_sha3_512();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int dlen = SHA512_DIGEST_LENGTH;
    if (!ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1
             || EVP_DigestUpdate(ctx, src, slen) != 1
             || EVP_DigestFinal_ex(ctx, dest, &dlen) != 1)
    {
        std::cerr << "SHA512_hash failed" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ctx);
}

// H1 : {0,1}* -> G1
inline void H1(const uint8_t *src, size_t slen, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(src, slen, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

// H2 : GT -> Zr
inline void H2(element_t t, int lenGT, element_t out)
{
    uint8_t *buf = new uint8_t[lenGT];
    element_to_bytes(buf, t);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(buf, lenGT, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
    delete[] buf;
}

// H3 : GT -> {0,1}^n12
inline void H3(element_t t, int lenGT, uint8_t *out)
{
    uint8_t *buf = new uint8_t[lenGT];
    element_to_bytes(buf, t);
    uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512_hash(buf, lenGT, digest);
    memcpy(out, digest, n12);
    delete[] buf;
}

// H3' : GT x Zr -> {0,1}^n12
inline void H3_prime(element_t t, int lenGT, element_t k, int lenZr, uint8_t *out)
{
    uint8_t *buf = new uint8_t[lenGT + lenZr];
    element_to_bytes(buf,         t);
    element_to_bytes(buf + lenGT, k);
    uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512_hash(buf, lenGT + lenZr, digest);
    memcpy(out, digest, n12);
    delete[] buf;
}

// H4 : {0,1}* -> Zr
inline void H4(const uint8_t *src, size_t slen, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(src, slen, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

inline double avg(const std::vector<double> &v)
{
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
}