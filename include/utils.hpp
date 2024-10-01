
#include <iostream>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "pbc.h"
#include "pbc_test.h"

#define MESSAGE_SPACE 32 // n1
#define ID_SPACE 32
#define Zp_SPACE 32 // n2

typedef struct
{
    element_t C1;
    element_t C2;
    element_t C3;
    uint8_t *C4;
} CIPHER;

typedef struct
{
    element_t key1;
    element_t key2;
} KEY;


void handleErrors(const char *errorMessage)
{
    std::cerr << "Error: " << errorMessage << std::endl;
    std::cerr << "Aborting..." << std::endl;
    std::exit(EXIT_FAILURE);
}


uint32_t SHA3_256(const uint8_t *src, const uint slen, uint8_t *&dest)
{
    const EVP_MD *md = EVP_sha3_256();
    EVP_MD_CTX *mdctx;
    uint32_t dlen = SHA256_DIGEST_LENGTH;

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        handleErrors("EVP_MD_CTX_create error occurred.");
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    { // returns 1 if successful
        handleErrors("EVP_DigestInit_ex error occurred.");
    }

    EVP_DigestUpdate(mdctx, src, slen);

    if ((dest = (uint8_t *)OPENSSL_malloc(dlen)) == NULL)
    {
        handleErrors("OPENSSL_malloc error occurred.");
    }
    memset(dest, 0x00, dlen);

    if (EVP_DigestFinal_ex(mdctx, dest, &dlen) != 1)
    { // returns 1 if successful
        OPENSSL_free(dest);
        handleErrors("EVP_DigestFinal_ex error occurred.");
    }

    EVP_MD_CTX_destroy(mdctx);

    return dlen;
}

uint32_t SHA3_512(const uint8_t *src, const uint slen, uint8_t *&dest)
{
    const EVP_MD *md = EVP_sha3_512();
    EVP_MD_CTX *mdctx;
    uint32_t dlen = SHA512_DIGEST_LENGTH;

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        handleErrors("EVP_MD_CTX_create error occurred.");
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    { // returns 1 if successful
        handleErrors("EVP_DigestInit_ex error occurred.");
    }

    EVP_DigestUpdate(mdctx, src, slen);

    if ((dest = (uint8_t *)OPENSSL_malloc(dlen)) == NULL)
    {
        handleErrors("OPENSSL_malloc error occurred.");
    }
    memset(dest, 0x00, dlen);

    if (EVP_DigestFinal_ex(mdctx, dest, &dlen) != 1)
    { // returns 1 if successful
        OPENSSL_free(dest);
        handleErrors("EVP_DigestFinal_ex error occurred.");
    }

    EVP_MD_CTX_destroy(mdctx);

    return dlen;
}

// H1 : {0, 1}* -> G
uint32_t H1(const uint8_t* src, const int slen, element_t & dest)
{
    uint8_t * tmp;
    int dlen = SHA3_256(src, slen, tmp);

    element_from_hash(dest, tmp, dlen);

    return dlen;
}

// H2 : GT -> Z_p^*
uint32_t H2(element_t _src, const int slen, element_t & dest)
{
    uint8_t * src = new uint8_t[slen];
    element_to_bytes(src, _src);

    uint8_t * tmp;
    int dlen = SHA3_256(src, slen, tmp);

    element_from_hash(dest, tmp, dlen);

    return dlen;
}

// H3 : GT -> {0, 1}^{n1 + n2}
uint32_t H3(element_t _src, const int slen, uint8_t *&dest)
{
    uint8_t * src = new uint8_t[slen];
    element_to_bytes(src, _src);
    int dlen = SHA3_512(src, slen, dest);

    return dlen;
}

// H3' : GT * Z_p^* -> {0, 1}^{n1 + n2}
uint32_t H3_prime(element_t src1, const int slen1, element_t src2, const int slen2, uint8_t *&dest)
{   
    int slen = slen1 + slen2;
    uint8_t * src = new uint8_t[slen];
    memset(src, 0x00, slen);

    uint8_t * str_src1 =  new uint8_t[slen1];
    memset(str_src1, 0x00, slen1);
    element_to_bytes(str_src1, src1);

    uint8_t * str_src2 =  new uint8_t[slen2];
    memset(str_src2, 0x00, slen2);
    element_to_bytes(str_src2, src2);
    
    memcpy(src, str_src1, slen1);
    memcpy(src + slen1, str_src2, slen2);

    int dlen = SHA3_512(src, slen, dest);

    return dlen;
}

// H4 : {0,1}^* -> Z_p^*
uint32_t H4(const uint8_t* src, const int slen, element_t & dest)
{
    uint8_t * tmp;
    int dlen = SHA3_256(src, slen, tmp);

    element_from_hash(dest, tmp, dlen);
    return dlen;
}
