#include "EZE20.h"

namespace EZE20
{

EZE20Scheme::EZE20Scheme(const std::string &param_str)
{
    if (pairing_init_set_str(pairing, param_str.c_str()) != 0)
    {
        std::cerr << "EZE20Scheme: pairing_init_set_str failed\n";
        std::exit(EXIT_FAILURE);
    }

    element_init_G1(g,    pairing);
    element_init_G1(mpk1, pairing);
    element_init_G1(mpk2, pairing);

    lenG1 = pairing_length_in_bytes_G1(pairing);
    lenGT = pairing_length_in_bytes_GT(pairing);
    lenZr = pairing_length_in_bytes_Zr(pairing);
}

EZE20Scheme::~EZE20Scheme()
{
    element_clear(g);
    element_clear(mpk1);
    element_clear(mpk2);
    pairing_clear(pairing);
}

void EZE20Scheme::setup(MasterSecretKey &msk)
{
    element_random(g);

    element_init_Zr(msk.s1, pairing);
    element_init_Zr(msk.s2, pairing);
    element_random(msk.s1);
    element_random(msk.s2);

    element_pow_zn(mpk1, g, msk.s1); // mpk1 = g^s1
    element_pow_zn(mpk2, g, msk.s2); // mpk2 = g^s2
}

void EZE20Scheme::extract(const std::string &id,
                           MasterSecretKey &msk,
                           DecryptionKey &dk)
{
    element_t hID;
    element_init_G1(hID, pairing);
    H1((const uint8_t *)id.data(), id.size(), hID);

    element_init_G1(dk.dk1, pairing);
    element_init_G1(dk.dk2, pairing);
    element_pow_zn(dk.dk1, hID, msk.s1); // dk1 = hID^s1
    element_pow_zn(dk.dk2, hID, msk.s2); // dk2 = hID^s2

    element_clear(hID);
}

void EZE20Scheme::encrypt(const std::string &id,
                           const uint8_t *M,
                           Ciphertext &C)
{
    element_t hID;
    element_init_G1(hID, pairing);
    H1((const uint8_t *)id.data(), id.size(), hID);

    element_t r1, r2;
    element_init_Zr(r1, pairing); element_random(r1);
    element_init_Zr(r2, pairing); element_random(r2);

    element_init_G1(C.C1, pairing); element_pow_zn(C.C1, g, r1); // C1 = g^r1
    element_init_G1(C.C2, pairing); element_pow_zn(C.C2, g, r2); // C2 = g^r2

    element_t m;
    element_init_Zr(m, pairing);
    H4(M, MESSAGE_SPACE, m);

    // C3 = m * r1 * H2(e(hID, mpk1)^r1)
    element_t hID_r1;
    element_init_G1(hID_r1, pairing);
    element_pow_zn(hID_r1, hID, r1);

    element_t e1;
    element_init_GT(e1, pairing);
    element_pairing(e1, hID_r1, mpk1); // e1 = e(hID, mpk1)^r1

    element_t h2val;
    element_init_Zr(h2val, pairing);
    H2(e1, lenGT, h2val);

    element_t mr1;
    element_init_Zr(mr1, pairing);
    element_mul(mr1, m, r1);

    element_init_Zr(C.C3, pairing);
    element_mul(C.C3, mr1, h2val); // C3 = (m*r1) * H2(e(hID,mpk1)^r1)

    // C4 = (M || r1) XOR H3(e(hID, mpk2)^r2)
    element_t hID_r2;
    element_init_G1(hID_r2, pairing);
    element_pow_zn(hID_r2, hID, r2);

    element_t e2;
    element_init_GT(e2, pairing);
    element_pairing(e2, hID_r2, mpk2); // e2 = e(hID, mpk2)^r2

    uint8_t h3buf[n12];
    H3(e2, lenGT, h3buf);

    uint8_t plain[n12] = {};
    memcpy(plain, M, MESSAGE_SPACE);
    element_to_bytes(plain + MESSAGE_SPACE, r1);

    for (int i = 0; i < n12; i++)
        C.C4[i] = plain[i] ^ h3buf[i];

    element_clear(hID);
    element_clear(r1);     element_clear(r2);
    element_clear(m);      element_clear(mr1);
    element_clear(hID_r1); element_clear(hID_r2);
    element_clear(e1);     element_clear(e2);
    element_clear(h2val);
}

bool EZE20Scheme::decrypt(DecryptionKey &dk,
                           Ciphertext &C,
                           uint8_t *M)
{
    element_t e2;
    element_init_GT(e2, pairing);
    element_pairing(e2, dk.dk2, C.C2); // e(dk2, C2) = e(hID, mpk2)^r2

    uint8_t h3buf[n12];
    H3(e2, lenGT, h3buf);

    uint8_t plain[n12];
    for (int i = 0; i < n12; i++)
        plain[i] = C.C4[i] ^ h3buf[i];

    uint8_t *M_dec  = plain;
    uint8_t *r1_buf = plain + MESSAGE_SPACE;

    element_t r1;
    element_init_Zr(r1, pairing);
    element_from_bytes(r1, r1_buf);

    // verify C1 = g^r1
    element_t chk;
    element_init_G1(chk, pairing);
    element_pow_zn(chk, g, r1);
    if (element_cmp(C.C1, chk))
    {
        element_clear(e2); element_clear(r1); element_clear(chk);
        return false;
    }

    // verify C3 = m*r1 * H2(e(hID,mpk1)^r1)
    element_t e1;
    element_init_GT(e1, pairing);
    element_pairing(e1, dk.dk1, C.C1); // e(dk1, C1) = e(hID, mpk1)^r1

    element_t h2val;
    element_init_Zr(h2val, pairing);
    H2(e1, lenGT, h2val);

    element_t m;
    element_init_Zr(m, pairing);
    H4(M_dec, MESSAGE_SPACE, m);

    element_t mr1;
    element_init_Zr(mr1, pairing);
    element_mul(mr1, m, r1);

    element_t k;
    element_init_Zr(k, pairing);
    element_div(k, C.C3, mr1); // k = C3 / (m*r1)

    if (element_cmp(h2val, k))
    {
        element_clear(e1); element_clear(e2);
        element_clear(h2val); element_clear(k);
        element_clear(r1); element_clear(chk);
        element_clear(m); element_clear(mr1);
        return false;
    }

    memcpy(M, M_dec, MESSAGE_SPACE);

    element_clear(e1); element_clear(e2);
    element_clear(h2val); element_clear(k);
    element_clear(r1); element_clear(chk);
    element_clear(m); element_clear(mr1);
    return true;
}

void EZE20Scheme::auth1(DecryptionKey &dk, Trapdoor1 &td)
{
    element_init_G1(td.td1, pairing);
    element_set(td.td1, dk.dk1);
}

bool EZE20Scheme::test1(Ciphertext &Ci, Trapdoor1 &tdi,
                         Ciphertext &Cj, Trapdoor1 &tdj)
{
    element_t ei, ej;
    element_init_GT(ei, pairing);
    element_init_GT(ej, pairing);
    element_pairing(ei, tdi.td1, Ci.C1);
    element_pairing(ej, tdj.td1, Cj.C1);

    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);
    H2(ei, lenGT, vi);
    H2(ej, lenGT, vj);

    element_div(vi, Ci.C3, vi); // Xi = C3i / H2(...)
    element_div(vj, Cj.C3, vj); // Xj = C3j / H2(...)

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, vj); // C1i^Xj
    element_pow_zn(rhs, Cj.C1, vi); // C1j^Xi

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(ei); element_clear(ej);
    element_clear(vi); element_clear(vj);
    element_clear(lhs); element_clear(rhs);
    return result;
}

void EZE20Scheme::auth2(DecryptionKey &dk, Ciphertext &C, Trapdoor2 &td)
{
    element_t e;
    element_init_GT(e, pairing);
    element_pairing(e, dk.dk1, C.C1);

    element_init_Zr(td.td2, pairing);
    H2(e, lenGT, td.td2);

    element_clear(e);
}

bool EZE20Scheme::test2(Ciphertext &Ci, Trapdoor2 &tdi,
                         Ciphertext &Cj, Trapdoor2 &tdj)
{
    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);
    element_div(vi, Ci.C3, tdi.td2);
    element_div(vj, Cj.C3, tdj.td2);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, vj);
    element_pow_zn(rhs, Cj.C1, vi);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(vi); element_clear(vj);
    element_clear(lhs); element_clear(rhs);
    return result;
}

void EZE20Scheme::auth3i(DecryptionKey &dk, Ciphertext &C, Trapdoor3i &td)
{
    element_t e;
    element_init_GT(e, pairing);
    element_pairing(e, dk.dk1, C.C1);

    element_init_Zr(td.td3, pairing);
    H2(e, lenGT, td.td3);

    element_clear(e);
}

void EZE20Scheme::auth3j(DecryptionKey &dk, Trapdoor3j &td)
{
    element_init_G1(td.td3, pairing);
    element_set(td.td3, dk.dk1);
}

bool EZE20Scheme::test3(Ciphertext &Ci, Trapdoor3i &tdi,
                         Ciphertext &Cj, Trapdoor3j &tdj)
{
    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);

    element_div(vi, Ci.C3, tdi.td3);

    element_t ej;
    element_init_GT(ej, pairing);
    element_pairing(ej, tdj.td3, Cj.C1);

    element_t h2ej;
    element_init_Zr(h2ej, pairing);
    H2(ej, lenGT, h2ej);
    element_div(vj, Cj.C3, h2ej);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, vj);
    element_pow_zn(rhs, Cj.C1, vi);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(vi);  element_clear(vj);
    element_clear(ej);  element_clear(h2ej);
    element_clear(lhs); element_clear(rhs);
    return result;
}

void EZE20Scheme::auth4(DecryptionKey &dk, Ciphertext &Ci, Ciphertext &Cj,
                         element_t gamma, Trapdoor4 &td)
{
    element_t e;
    element_init_GT(e, pairing);
    element_pairing(e, dk.dk1, Ci.C1);

    element_t h2e;
    element_init_Zr(h2e, pairing);
    H2(e, lenGT, h2e);

    element_init_Zr(td.TD1, pairing);
    element_div(td.TD1, gamma, h2e);

    element_init_G1(td.TD2, pairing);
    element_pow_zn(td.TD2, Cj.C1, gamma);

    element_clear(e);
    element_clear(h2e);
}

bool EZE20Scheme::test4(Ciphertext &Ci, Trapdoor4 &tdi,
                         Ciphertext &Cj, Trapdoor4 &tdj)
{
    element_t Xi, Xj;
    element_init_Zr(Xi, pairing);
    element_init_Zr(Xj, pairing);
    element_mul(Xi, Ci.C3, tdi.TD1);
    element_mul(Xj, Ci.C3, tdj.TD1); 

    element_t CjXi, CiXj;
    element_init_G1(CjXi, pairing);
    element_init_G1(CiXj, pairing);
    element_pow_zn(CjXi, Cj.C1, Xi);
    element_pow_zn(CiXj, Ci.C1, Xj);

    element_t divtd;
    element_init_G1(divtd, pairing);
    element_div(divtd, tdi.TD2, tdj.TD2);

    element_t divC;
    element_init_G1(divC, pairing);
    element_div(divC, Ci.C1, Cj.C1);

    element_t cmp1, cmp2;
    element_init_G1(cmp1, pairing);
    element_init_G1(cmp2, pairing);
    element_div(cmp1, CjXi, CiXj);
    element_mul(cmp2, divtd, divC);

    bool result = (element_cmp(cmp1, cmp2) == 0);

    element_clear(Xi);    element_clear(Xj);
    element_clear(CjXi);  element_clear(CiXj);
    element_clear(divtd); element_clear(divC);
    element_clear(cmp1);  element_clear(cmp2);
    return result;
}


void EZE20Scheme::Random_Zr(element_t &r)
{
    element_init_Zr(r, pairing);
    element_random(r);
}

} // namespace EZE20