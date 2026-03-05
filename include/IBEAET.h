#pragma once

#include <string>
#include <cstdint>
#include <cstring>
#include <iostream>

#include <pbc/pbc.h>
#include "utils.h"

namespace IBEAET
{

class IBEAETScheme
{
public:
    pairing_t pairing;
    element_t g;
    element_t mpk1;
    element_t mpk2;

    int lenG1, lenGT, lenZr;

    IBEAETScheme(const std::string &param_str);
    ~IBEAETScheme();

    void setup(MasterSecretKey &msk);
    void extract(const std::string &id, MasterSecretKey &msk, DecryptionKey &dk);
    void encrypt(const std::string &id, const uint8_t *M, Ciphertext &C);
    bool decrypt(DecryptionKey &dk, Ciphertext &C, uint8_t *M);

    void auth1(DecryptionKey &dk, Trapdoor1 &td);
    bool test1(Ciphertext &Ci, Trapdoor1 &tdi, Ciphertext &Cj, Trapdoor1 &tdj);

    void auth2(DecryptionKey &dk, Ciphertext &C, Trapdoor2 &td);
    bool test2(Ciphertext &Ci, Trapdoor2 &tdi, Ciphertext &Cj, Trapdoor2 &tdj);

    void auth3i(DecryptionKey &dk, Ciphertext &C, Trapdoor3i &td);
    void auth3j(DecryptionKey &dk, Trapdoor3j &td);
    bool test3(Ciphertext &Ci, Trapdoor3i &tdi, Ciphertext &Cj, Trapdoor3j &tdj);

    void auth4(DecryptionKey &dk, Ciphertext &Ci, Ciphertext &Cj,
               element_t gamma, Trapdoor4 &td);
    bool test4(Ciphertext &Ci, Trapdoor4 &tdi, Ciphertext &Cj, Trapdoor4 &tdj);

    void Random_Zr(element_t &r);
};

} // namespace IBEAET