#include "IBEAET.hpp"
#include <iostream>
#include <cstring>
#include <fstream>
#include <string>

#define ITERCNT 1
#define TESTCNT 1

IBEAET::IBEAET()
{
    init();
}

IBEAET::IBEAET(int argc, char **argv)
{
    pbc_demo_pairing_init(pairing, argc, argv);
    init();
}

void IBEAET::init()
{
    element_init_G1(g, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);

    element_random(g);
    element_random(s1);
    element_random(s2);

    element_pow_zn(g1, g, s1); // g1 = g^s1
    element_pow_zn(g2, g, s2); // g2 = g^s2

    lenG1 = pairing_length_in_bytes_G1(pairing);
    lenGT = pairing_length_in_bytes_GT(pairing);
    lenZr = pairing_length_in_bytes_Zr(pairing);
}

void IBEAET::clear()
{
    element_clear(s1);
    element_clear(s2);
    element_clear(g);
    element_clear(g1);
    element_clear(g2);
    pairing_clear(pairing);
}

IBEAET::~IBEAET()
{
    this->clear();
}

KEY *IBEAET::Extract(const uint8_t *ID)
{
    element_t HID;
    element_init_G1(HID, pairing);
    int dlen = H1(ID, ID_SPACE, HID);

    KEY *dk = new KEY;
    element_init_G1(dk->key1, pairing);
    element_init_G1(dk->key2, pairing);

    element_pow_zn(dk->key1, HID, s1); // dk1 = HID^s1
    element_pow_zn(dk->key2, HID, s2); // dk2 = HID^s2

    element_clear(HID);

    return dk;
}

CIPHER *IBEAET::Encrypt(const uint8_t *ID, const uint8_t *M)
{
    CIPHER *C = new CIPHER;

    element_t HID; //  HID = H1(M), m = H4(M)
    element_init_G1(HID, pairing);
    int dlen = H1(ID, ID_SPACE, HID);

    element_t m;
    element_init_Zr(m, pairing);
    dlen = H4(M, MESSAGE_SPACE, m);

    element_t r1;
    element_init_Zr(r1, pairing);
    element_random(r1);

    element_t r2;
    element_init_Zr(r2, pairing);
    element_random(r2);

    // compute C1 and C2.
    element_init_G1(C->C1, pairing);
    element_pow_zn(C->C1, g, r1); // C1 = g^r1

    element_init_G1(C->C2, pairing);
    element_pow_zn(C->C2, g, r2); // C2 = g^r2

    // C3_Left = m * r1
    element_t C3_Left;
    element_init_Zr(C3_Left, pairing);
    element_mul_zn(C3_Left, m, r1);

    element_t tmp1;
    element_init_G1(tmp1, pairing);
    element_pow_zn(tmp1, HID, r1); // tmp1 = HID^r1

    element_t C3_Pair;
    element_init_GT(C3_Pair, pairing);
    element_pairing(C3_Pair, tmp1, g1); // C3_Pair = e(tmp1, g1) = e(HID, g1)^r1

    // C3_Right = H2(e(h_ID, g_1) ^r1)
    element_t C3_Right;
    element_init_Zr(C3_Right, pairing);
    dlen = H2(C3_Pair, lenGT, C3_Right);

    // C3 = (m * r1) * H2(e(h_ID, g_1) ^r1)
    element_init_Zr(C->C3, pairing);
    element_mul_zn(C->C3, C3_Left, C3_Right);

    // compute C4 = (M || r1) ^ H3(e(HID, g2)^r2 ||(m * r1))
    uint8_t *strR1 = new uint8_t[Zp_SPACE];
    element_to_bytes(strR1, r1);

    uint8_t *strC4_Left = new uint8_t[MESSAGE_SPACE + Zp_SPACE];
    memset(strC4_Left, 0x00, MESSAGE_SPACE + Zp_SPACE);

    memcpy(strC4_Left, M, MESSAGE_SPACE);
    memcpy(strC4_Left + MESSAGE_SPACE, strR1, Zp_SPACE);

    element_t tmp2;
    element_init_G1(tmp2, pairing);
    element_pow_zn(tmp2, HID, r2); // tmp2 = HID^r2

    element_t C4_Pair;
    element_init_GT(C4_Pair, pairing);
    element_pairing(C4_Pair, tmp2, g2); // C4_Pair = e(tmp2, g2) = e(HID, g2)^r2

    uint8_t *strC4_Right;
    dlen = H3(C4_Pair, lenGT, strC4_Right);

    C->C4 = new uint8_t[MESSAGE_SPACE + Zp_SPACE];
    memset(C->C4, 0x00, MESSAGE_SPACE + Zp_SPACE);
    for (int i = 0; i < MESSAGE_SPACE + Zp_SPACE; i++)
    {
        C->C4[i] = strC4_Left[i] ^ strC4_Right[i];
    }

    element_clear(r1);
    element_clear(r2);
    element_clear(HID);
    element_clear(m);
    element_clear(C3_Left);
    element_clear(C3_Pair);
    element_clear(C3_Right);
    element_clear(C4_Pair);

    delete[] strR1;
    delete[] strC4_Left;
    delete[] strC4_Right;

    return C;
}

uint8_t *IBEAET::Decrypt(KEY &dk, CIPHER &C)
{
    element_t C3_Pair;
    element_init_GT(C3_Pair, pairing);
    element_pairing(C3_Pair, dk.key1, C.C1);

    element_t C4_Pair;
    element_init_GT(C4_Pair, pairing);
    element_pairing(C4_Pair, dk.key2, C.C2);

    uint8_t *strC4_Right;
    int dlen = H3(C4_Pair, lenGT, strC4_Right);

    uint8_t *strC4_Left = new uint8_t[SHA512_DIGEST_LENGTH];
    for (int i = 0; i < MESSAGE_SPACE + Zp_SPACE; i++)
        strC4_Left[i] = C.C4[i] ^ strC4_Right[i];

    uint8_t *M = new uint8_t[MESSAGE_SPACE];
    memset(M, 0x00, MESSAGE_SPACE);
    memcpy(M, strC4_Left, MESSAGE_SPACE);

    uint8_t *strR1 = new uint8_t[Zp_SPACE];
    memset(strR1, 0x00, Zp_SPACE);
    memcpy(strR1, strC4_Left + MESSAGE_SPACE, Zp_SPACE);

    element_t r1;
    element_init_Zr(r1, pairing);
    element_from_bytes(r1, strR1);

    element_t m;
    element_init_Zr(m, pairing);
    dlen = H4(M, MESSAGE_SPACE, m);

    element_t C3_Left;
    element_init_Zr(C3_Left, pairing);
    element_mul_zn(C3_Left, m, r1);

    element_t C3_Right;
    element_init_Zr(C3_Right, pairing);
    dlen = H2(C3_Pair, lenGT, C3_Right);
    element_t k;
    element_init_Zr(k, pairing);
    element_div(k, C.C3, C3_Left);

    element_t verifyC1;
    element_init_G1(verifyC1, pairing);
    element_pow_zn(verifyC1, g, r1);

    if (element_cmp(verifyC1, C.C1) || element_cmp(C3_Right, k))
    {
        printf("Decryption phase : verification fails\n");
        abort();
    }

    delete[] strR1;
    delete[] strC4_Left;
    delete[] strC4_Right;
    element_clear(k);
    element_clear(verifyC1);
    element_clear(C3_Left);
    element_clear(C3_Right);
    element_clear(C3_Pair);
    element_clear(C4_Pair);
    element_clear(m);
    element_clear(r1);

    return M;
}

void IBEAET::aut1(KEY &dk, element_t &td)
{
    element_init_G1(td, pairing);
    element_set(td, dk.key1);
}

void IBEAET::aut2(KEY &dk, CIPHER &C, element_t &td)
{
    element_t pair;
    element_init_GT(pair, pairing);
    element_pairing(pair, C.C1, dk.key1);

    element_init_Zr(td, pairing);

    int dlen = H2(pair, lenGT, td);

    element_clear(pair);
}

void IBEAET::aut3i(KEY &dk, CIPHER &C, element_t &td)
{
    aut2(dk, C, td);
}

void IBEAET::aut3j(KEY &dk, element_t &td)
{
    aut1(dk, td);
}

void IBEAET::aut4(KEY &dk, CIPHER &Ci, CIPHER &Cj, element_t y, element_t td[2])
{
    element_t pair;
    element_init_GT(pair, pairing);
    element_pairing(pair, Ci.C1, dk.key1);

    element_t tmp;
    element_init_Zr(tmp, pairing);
    int dlen = H2(pair, lenGT, tmp);

    element_init_Zr(td[0], pairing);
    element_div(td[0], y, tmp);

    element_init_G1(td[1], pairing);
    element_pow_zn(td[1], Cj.C1, y);

    element_clear(tmp);
    element_clear(pair);
}

bool IBEAET::test1(CIPHER &Ci, element_t tdi, CIPHER &Cj, element_t tdj)
{

    element_t pairi;
    element_init_GT(pairi, pairing);
    element_pairing(pairi, tdi, Ci.C1);

    element_t pairj;
    element_init_GT(pairj, pairing);
    element_pairing(pairj, tdj, Cj.C1);

    element_t hashi;
    element_init_Zr(hashi, pairing);
    int dlen = H2(pairi, lenGT, hashi);

    element_t hashj;
    element_init_Zr(hashj, pairing);
    dlen = H2(pairj, lenGT, hashj);

    element_t Xi;
    element_init_Zr(Xi, pairing);
    element_div(Xi, Ci.C3, hashi);

    element_t Xj;
    element_init_Zr(Xj, pairing);
    element_div(Xj, Cj.C3, hashj);

    element_t cmpCi;
    element_init_G1(cmpCi, pairing);
    element_pow_zn(cmpCi, Ci.C1, Xj);

    element_t cmpCj;
    element_init_G1(cmpCj, pairing);
    element_pow_zn(cmpCj, Cj.C1, Xi);

    bool ret = false;
    if (!element_cmp(cmpCi, cmpCj))
        ret = true;
    else
        ret = false;

    element_clear(Xi);
    element_clear(Xj);
    element_clear(cmpCi);
    element_clear(cmpCj);
    element_clear(pairi);
    element_clear(pairj);
    element_clear(hashi);
    element_clear(hashj);

    return ret;
}

bool IBEAET::test2(CIPHER &Ci, element_t tdi, CIPHER &Cj, element_t tdj)
{
    element_t Xi;
    element_init_Zr(Xi, pairing);
    element_div(Xi, Ci.C3, tdi);

    element_t Xj;
    element_init_Zr(Xj, pairing);
    element_div(Xj, Cj.C3, tdj);

    element_t cmpCi;
    element_init_G1(cmpCi, pairing);
    element_pow_zn(cmpCi, Ci.C1, Xj);

    element_t cmpCj;
    element_init_G1(cmpCj, pairing);
    element_pow_zn(cmpCj, Cj.C1, Xi);

    bool ret = false;
    if (!element_cmp(cmpCi, cmpCj))
        ret = true;
    else
        ret = false;

    element_clear(Xi);
    element_clear(Xj);
    element_clear(cmpCi);
    element_clear(cmpCj);

    return ret;
}

bool IBEAET::test3(CIPHER &Ci, element_t tdi, CIPHER &Cj, element_t tdj)
{
    element_t pairj;
    element_init_GT(pairj, pairing);
    element_pairing(pairj, tdj, Cj.C1);

    element_t hashj;
    element_init_Zr(hashj, pairing);
    int dlen = H2(pairj, lenGT, hashj);

    element_t Xi;
    element_init_Zr(Xi, pairing);
    element_div(Xi, Ci.C3, tdi);

    element_t Xj;
    element_init_Zr(Xj, pairing);
    element_div(Xj, Cj.C3, hashj);

    element_t cmpCi;
    element_init_G1(cmpCi, pairing);
    element_pow_zn(cmpCi, Ci.C1, Xj);

    element_t cmpCj;
    element_init_G1(cmpCj, pairing);
    element_pow_zn(cmpCj, Cj.C1, Xi);

    bool ret = false;
    if (!element_cmp(cmpCi, cmpCj))
        ret = true;
    else
        ret = false;

    element_clear(Xi);
    element_clear(Xj);

    element_clear(cmpCi);
    element_clear(cmpCj);
    element_clear(pairj);
    element_clear(hashj);

    return ret;
}

bool IBEAET::test4(CIPHER &Ci, element_t tdi[2], CIPHER &Cj, element_t tdj[2])
{
    element_t Xi;
    element_init_Zr(Xi, pairing);
    element_mul_zn(Xi, Ci.C3, tdi[0]);

    element_t Xj;
    element_init_Zr(Xj, pairing);
    element_mul_zn(Xj, Ci.C3, tdj[0]);

    element_t CjXi;
    element_init_G1(CjXi, pairing);
    element_pow_zn(CjXi, Cj.C1, Xi);

    element_t CiXj;
    element_init_G1(CiXj, pairing);
    element_pow_zn(CiXj, Ci.C1, Xj);

    element_t divtd;
    element_init_G1(divtd, pairing);
    element_div(divtd, tdi[1], tdj[1]);

    element_t divC;
    element_init_G1(divC, pairing);
    element_div(divC, Ci.C1, Cj.C1);

    element_t cmp1;
    element_init_G1(cmp1, pairing);
    element_div(cmp1, CjXi, CiXj);

    element_t cmp2;
    element_init_G1(cmp2, pairing);
    element_mul(cmp2, divtd, divC);

    bool ret = false;
    if (!element_cmp(cmp1, cmp2))
        ret = true;
    else
        ret = false;

    element_clear(Xi);
    element_clear(Xj);
    element_clear(CjXi);
    element_clear(CiXj);
    element_clear(divtd);
    element_clear(divC);
    element_clear(cmp1);
    element_clear(cmp2);
    return ret;
}

pairing_t *IBEAET::getPairing()
{
    return &this->pairing;
}

int IBEAET::getLenG1()
{
    return this->lenG1;
}
int IBEAET::getLenGT()
{
    return this->lenGT;
}
int IBEAET::getLenZr()
{
    return this->lenZr;
}

void IBEAET::Random_Zr(element_t &r)
{
    element_init_Zr(r, pairing);
    element_random(r);
}

// int main(int argc, char *argv[])
// {
//     IBEAET IBEAET(argc, argv);

//     uint8_t *IDi = new uint8_t[ID_SPACE];
//     uint8_t *IDj = new uint8_t[ID_SPACE];
//     uint8_t *MSG = new uint8_t[MESSAGE_SPACE];

//     memset(IDi, 0x00, ID_SPACE);
//     memset(IDj, 0x00, ID_SPACE);
//     memset(MSG, 0x00, MESSAGE_SPACE);

//     strcpy((char *)IDi, "IDIDIDIDIDID");
//     strcpy((char *)IDj, "IDIDIDIDIDIDID");
//     strcpy((char *)MSG, "MSGMSGMSGMSGMSGMSG");

//     KEY *dki = IBEAET.Extract(IDi);
//     KEY *dkj = IBEAET.Extract(IDj);

//     CIPHER *Ci = IBEAET.Encrypt(IDi, MSG);
//     uint8_t *MSG1 = IBEAET.Decrypt(*dki, *Ci);

//     CIPHER *Cj = IBEAET.Encrypt(IDj, MSG);
//     uint8_t *MSG2 = IBEAET.Decrypt(*dkj, *Cj);

//     if (strcmp((char *)MSG, (char *)MSG1) || strcmp((char *)MSG, (char *)MSG2))
//     {
//         printf("not equal to message\n");
//     }

//     element_t tdi1;
//     IBEAET.aut1(*dki, tdi1);

//     element_t tdj1;
//     IBEAET.aut1(*dkj, tdj1);

//     if (!IBEAET.test1(*Ci, tdi1, *Cj, tdj1))
//     {
//         printf("test1 fails\n");
//         abort();
//     }

//     element_t tdi2;
//     IBEAET.aut2(*dki, *Ci, tdi2);

//     element_t tdj2;
//     IBEAET.aut2(*dkj, *Cj, tdj2);

//     if (!IBEAET.test2(*Ci, tdi2, *Cj, tdj2))
//     {
//         printf("test2 fails\n");
//         abort();
//     }

//     element_t tdi3;
//     IBEAET.aut3i(*dki, *Ci, tdi3);

//     element_t tdj3;
//     IBEAET.aut3j(*dkj, tdj3);

//     if (!IBEAET.test3(*Ci, tdi3, *Cj, tdj3))
//     {
//         printf("test3 fails\n");
//         abort();
//     }

//     element_t yi;
//     IBEAET.Random_Zr(yi);

//     element_t yj;
//     IBEAET.Random_Zr(yj);

//     element_t tdi4[2];
//     IBEAET.aut4(*dki, *Ci, *Cj, yi, tdi4);

//     element_t tdj4[2];
//     IBEAET.aut4(*dkj, *Cj, *Ci, yj, tdj4);

//     if (!IBEAET.test4(*Ci, tdi4, *Cj, tdj4))
//     {
//         printf("test4 fails\n");
//         abort();
//     }

//     return 0;
// }