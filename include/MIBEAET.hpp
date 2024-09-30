#include "utils.hpp"

class MIBEAET
{

private:
    pairing_t pairing;
    element_t s1, s2;    // master secret key
    element_t g, g1, g2; // public parameters
    int lenG1;
    int lenGT;
    int lenZr;

public:
    MIBEAET();
    MIBEAET(int argc, char **argv);
    ~MIBEAET();

    void init();
    void clear();
    KEY *Extract(const uint8_t *ID);
    CIPHER *Encrypt(const uint8_t *ID, const uint8_t *M);
    uint8_t *Decrypt(KEY &dk, CIPHER &C);

    void aut1(KEY &dk, element_t &td);
    void aut2(KEY &dk, CIPHER &C, element_t &td);
    void aut3i(KEY &dk, CIPHER &C, element_t &td);
    void aut3j(KEY &dk, element_t &td);
    void aut4(KEY &dki, CIPHER &Ci, CIPHER &Cj, element_t y, element_t td[2]);

    bool test1(CIPHER &Ci, element_t tdi, CIPHER &Cj, element_t tdj);
    bool test2(CIPHER &Ci, element_t tdi, CIPHER &Cj, element_t tdj);
    bool test3(CIPHER &Ci, element_t tdi, CIPHER &Cj, element_t tdj);
    bool test4(CIPHER &Ci, element_t tdi[2], CIPHER &Cj, element_t tdj[2]);

    int getLenG1();
    int getLenGT();
    int getLenZr();

    pairing_t *getPairing();
    void Random_Zr(element_t & r);
};
