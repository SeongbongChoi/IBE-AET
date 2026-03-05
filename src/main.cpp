#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <chrono>
#include <vector>
#include <cstdlib>
#include <string>

#include "IBEAET.h"
#include "EZE20.h"

using namespace std::chrono;

static void print_pass(const char *label) { std::cout << "  [PASS] " << label << "\n"; }
static void print_fail(const char *label) { std::cerr << "  [FAIL] " << label << "\n"; }
static void check(bool ok, const char *label) { ok ? print_pass(label) : print_fail(label); }

static void run_ibeaet(int N, const std::string &param_str)
{
    using namespace IBEAET;

    std::cout << "\n=== [IBEAET] Correctness Verification ===\n";

    IBEAETScheme scheme(param_str);
    MasterSecretKey msk;
    scheme.setup(msk);

    const std::string id_alice = "alice@example.com";
    const std::string id_bob   = "bob@example.com";

    uint8_t msg_orig[MESSAGE_SPACE];
    memset(msg_orig, 0xAB, MESSAGE_SPACE);

    DecryptionKey dk_alice, dk_bob;
    scheme.extract(id_alice, msk, dk_alice);
    scheme.extract(id_bob,   msk, dk_bob);

    {
        Ciphertext C;
        scheme.encrypt(id_alice, msg_orig, C);

        uint8_t msg_dec[MESSAGE_SPACE] = {};
        bool ok = scheme.decrypt(dk_alice, C, msg_dec);
        check(ok && memcmp(msg_orig, msg_dec, MESSAGE_SPACE) == 0,
              "Encrypt -> Decrypt (correct key)");

        uint8_t msg_bad[MESSAGE_SPACE] = {};
        bool bad = scheme.decrypt(dk_bob, C, msg_bad);
        check(!bad, "Decrypt with wrong key returns false");

        element_clear(C.C1); element_clear(C.C2); element_clear(C.C3);
    }

    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        Trapdoor1 tdi, tdj, tdk;
        scheme.auth1(dk_alice, tdi);
        scheme.auth1(dk_alice, tdj);
        scheme.auth1(dk_alice, tdk);

        check( scheme.test1(Ci, tdi, Cj, tdj), "Type-1: same plaintext -> true");
        check(!scheme.test1(Ci, tdi, Ck, tdk), "Type-1: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.td1); element_clear(tdj.td1); element_clear(tdk.td1);
    }

    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        Trapdoor2 tdi, tdj, tdk;
        scheme.auth2(dk_alice, Ci, tdi);
        scheme.auth2(dk_alice, Cj, tdj);
        scheme.auth2(dk_alice, Ck, tdk);

        check( scheme.test2(Ci, tdi, Cj, tdj), "Type-2: same plaintext -> true");
        check(!scheme.test2(Ci, tdi, Ck, tdk), "Type-2: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.td2); element_clear(tdj.td2); element_clear(tdk.td2);
    }

    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        Trapdoor3i tdi, tdk;
        Trapdoor3j tdj, tdl;
        scheme.auth3i(dk_alice, Ci, tdi);
        scheme.auth3j(dk_alice,     tdj);
        scheme.auth3i(dk_alice, Ck, tdk);
        scheme.auth3j(dk_alice,     tdl);

        check( scheme.test3(Ci, tdi, Cj, tdj), "Type-3: same plaintext -> true");
        check(!scheme.test3(Ck, tdk, Ci, tdl), "Type-3: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.td3); element_clear(tdj.td3);
        element_clear(tdk.td3); element_clear(tdl.td3);
    }

    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        element_t gamma;
        element_init_Zr(gamma, scheme.pairing);
        element_random(gamma);

        Trapdoor4 tdi, tdj, tdk, tdl;
        scheme.auth4(dk_alice, Ci, Cj, gamma, tdi);
        scheme.auth4(dk_alice, Cj, Ci, gamma, tdj);
        scheme.auth4(dk_alice, Ci, Ck, gamma, tdk);
        scheme.auth4(dk_alice, Ck, Ci, gamma, tdl);

        check( scheme.test4(Ci, tdi, Cj, tdj), "Type-4: same plaintext -> true");
        check(!scheme.test4(Ci, tdk, Ck, tdl), "Type-4: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.TD1); element_clear(tdi.TD2);
        element_clear(tdj.TD1); element_clear(tdj.TD2);
        element_clear(tdk.TD1); element_clear(tdk.TD2);
        element_clear(tdl.TD1); element_clear(tdl.TD2);
        element_clear(gamma);
    }

    std::cout << "\n=== [IBEAET] Benchmark: N=" << N << " ===\n";

    std::vector<double> t_setup, t_extract, t_encrypt, t_decrypt;
    std::vector<double> t_auth1, t_test1;
    std::vector<double> t_auth2, t_test2;
    std::vector<double> t_auth3i, t_auth3j, t_test3;
    std::vector<double> t_auth4, t_test4;

    for (int i = 0; i < N; i++)
    {
        MasterSecretKey tmp;
        auto t0 = high_resolution_clock::now();
        scheme.setup(tmp);
        t_setup.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        element_clear(tmp.s1); element_clear(tmp.s2);
    }

    for (int i = 0; i < N; i++)
    {
        DecryptionKey dk;
        auto t0 = high_resolution_clock::now();
        scheme.extract(id_alice, msk, dk);
        t_extract.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        element_clear(dk.dk1); element_clear(dk.dk2);
    }

    std::vector<Ciphertext> ctxts(N + 1);
    for (int i = 0; i <= N; i++)
    {
        auto t0 = high_resolution_clock::now();
        scheme.encrypt(id_alice, msg_orig, ctxts[i]);
        if (i < N)
            t_encrypt.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
    }

    for (int i = 0; i < N; i++)
    {
        uint8_t dec[MESSAGE_SPACE] = {};
        auto t0 = high_resolution_clock::now();
        scheme.decrypt(dk_alice, ctxts[i], dec);
        t_decrypt.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
    }

    {
        std::vector<Trapdoor1> td1s(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth1(dk_alice, td1s[i]);
            if (i < N)
                t_auth1.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test1(ctxts[i], td1s[i], ctxts[i + 1], td1s[i + 1]);
            t_test1.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++) element_clear(td1s[i].td1);
    }

    {
        std::vector<Trapdoor2> td2s(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth2(dk_alice, ctxts[i], td2s[i]);
            if (i < N)
                t_auth2.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test2(ctxts[i], td2s[i], ctxts[i + 1], td2s[i + 1]);
            t_test2.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++) element_clear(td2s[i].td2);
    }

    {
        std::vector<Trapdoor3i> td3is(N + 1);
        std::vector<Trapdoor3j> td3js(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth3i(dk_alice, ctxts[i], td3is[i]);
            if (i < N)
                t_auth3i.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth3j(dk_alice, td3js[i]);
            if (i < N)
                t_auth3j.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test3(ctxts[i], td3is[i], ctxts[i + 1], td3js[i + 1]);
            t_test3.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++)
        {
            element_clear(td3is[i].td3);
            element_clear(td3js[i].td3);
        }
    }

    {
        element_t gamma;
        element_init_Zr(gamma, scheme.pairing);
        element_random(gamma);

        std::vector<Trapdoor4> td4s(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth4(dk_alice, ctxts[i], ctxts[(i + 1) % (N + 1)], gamma, td4s[i]);
            if (i < N)
                t_auth4.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test4(ctxts[i], td4s[i], ctxts[i + 1], td4s[i + 1]);
            t_test4.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++)
        {
            element_clear(td4s[i].TD1);
            element_clear(td4s[i].TD2);
        }
        element_clear(gamma);
    }

    std::cout << "Setup   : " << avg(t_setup)   << " ms\n";
    std::cout << "Extract : " << avg(t_extract) << " ms\n";
    std::cout << "Encrypt : " << avg(t_encrypt) << " ms\n";
    std::cout << "Decrypt : " << avg(t_decrypt) << " ms\n";
    std::cout << "Auth1   : " << avg(t_auth1)   << " ms\n";
    std::cout << "Test1   : " << avg(t_test1)   << " ms\n";
    std::cout << "Auth2   : " << avg(t_auth2)   << " ms\n";
    std::cout << "Test2   : " << avg(t_test2)   << " ms\n";
    std::cout << "Auth3i  : " << avg(t_auth3i)  << " ms\n";
    std::cout << "Auth3j  : " << avg(t_auth3j)  << " ms\n";
    std::cout << "Test3   : " << avg(t_test3)   << " ms\n";
    std::cout << "Auth4   : " << avg(t_auth4)   << " ms\n";
    std::cout << "Test4   : " << avg(t_test4)   << " ms\n";

    for (int i = 0; i <= N; i++)
    {
        element_clear(ctxts[i].C1);
        element_clear(ctxts[i].C2);
        element_clear(ctxts[i].C3);
    }
    element_clear(dk_alice.dk1); element_clear(dk_alice.dk2);
    element_clear(dk_bob.dk1);   element_clear(dk_bob.dk2);
    element_clear(msk.s1);       element_clear(msk.s2);
}

static void run_eze20(int N, const std::string &param_str)
{
    using namespace EZE20;

    std::cout << "\n=== [EZE20] Correctness Verification ===\n";

    EZE20Scheme scheme(param_str);
    MasterSecretKey msk;
    scheme.setup(msk);

    const std::string id_alice = "alice@example.com";
    const std::string id_bob   = "bob@example.com";

    uint8_t msg_orig[MESSAGE_SPACE];
    memset(msg_orig, 0xAB, MESSAGE_SPACE);

    DecryptionKey dk_alice, dk_bob;
    scheme.extract(id_alice, msk, dk_alice);
    scheme.extract(id_bob,   msk, dk_bob);

    {
        Ciphertext C;
        scheme.encrypt(id_alice, msg_orig, C);

        uint8_t msg_dec[MESSAGE_SPACE] = {};
        bool ok = scheme.decrypt(dk_alice, C, msg_dec);
        check(ok && memcmp(msg_orig, msg_dec, MESSAGE_SPACE) == 0,
              "Encrypt -> Decrypt (correct key)");

        uint8_t msg_bad[MESSAGE_SPACE] = {};
        bool bad = scheme.decrypt(dk_bob, C, msg_bad);
        check(!bad, "Decrypt with wrong key returns false");

        element_clear(C.C1); element_clear(C.C2); element_clear(C.C3);
    }

    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        Trapdoor1 tdi, tdj, tdk;
        scheme.auth1(dk_alice, tdi);
        scheme.auth1(dk_alice, tdj);
        scheme.auth1(dk_alice, tdk);

        check( scheme.test1(Ci, tdi, Cj, tdj), "Type-1: same plaintext -> true");
        check(!scheme.test1(Ci, tdi, Ck, tdk), "Type-1: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.td1); element_clear(tdj.td1); element_clear(tdk.td1);
    }

    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        Trapdoor2 tdi, tdj, tdk;
        scheme.auth2(dk_alice, Ci, tdi);
        scheme.auth2(dk_alice, Cj, tdj);
        scheme.auth2(dk_alice, Ck, tdk);

        check( scheme.test2(Ci, tdi, Cj, tdj), "Type-2: same plaintext -> true");
        check(!scheme.test2(Ci, tdi, Ck, tdk), "Type-2: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.td2); element_clear(tdj.td2); element_clear(tdk.td2);
    }

    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        Trapdoor3i tdi, tdk;
        Trapdoor3j tdj, tdl;
        scheme.auth3i(dk_alice, Ci, tdi);
        scheme.auth3j(dk_alice,     tdj);
        scheme.auth3i(dk_alice, Ck, tdk);
        scheme.auth3j(dk_alice,     tdl);

        check( scheme.test3(Ci, tdi, Cj, tdj), "Type-3: same plaintext -> true");
        check(!scheme.test3(Ck, tdk, Ci, tdl), "Type-3: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.td3); element_clear(tdj.td3);
        element_clear(tdk.td3); element_clear(tdl.td3);
    }

    // ---- Type-4 ----
    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        uint8_t msg2[MESSAGE_SPACE]; memset(msg2, 0xCD, MESSAGE_SPACE);
        scheme.encrypt(id_alice, msg2, Ck);

        element_t gamma;
        element_init_Zr(gamma, scheme.pairing);
        element_random(gamma);

        Trapdoor4 tdi, tdj, tdk, tdl;
        scheme.auth4(dk_alice, Ci, Cj, gamma, tdi);
        scheme.auth4(dk_alice, Cj, Ci, gamma, tdj);
        scheme.auth4(dk_alice, Ci, Ck, gamma, tdk);
        scheme.auth4(dk_alice, Ck, Ci, gamma, tdl);

        check( scheme.test4(Ci, tdi, Cj, tdj), "Type-4: same plaintext -> true");
        check(!scheme.test4(Ci, tdk, Ck, tdl), "Type-4: diff plaintext -> false");

        element_clear(Ci.C1); element_clear(Ci.C2); element_clear(Ci.C3);
        element_clear(Cj.C1); element_clear(Cj.C2); element_clear(Cj.C3);
        element_clear(Ck.C1); element_clear(Ck.C2); element_clear(Ck.C3);
        element_clear(tdi.TD1); element_clear(tdi.TD2);
        element_clear(tdj.TD1); element_clear(tdj.TD2);
        element_clear(tdk.TD1); element_clear(tdk.TD2);
        element_clear(tdl.TD1); element_clear(tdl.TD2);
        element_clear(gamma);
    }

    std::cout << "\n=== [EZE20] Benchmark: N=" << N << " ===\n";

    std::vector<double> t_setup, t_extract, t_encrypt, t_decrypt;
    std::vector<double> t_auth1, t_test1;
    std::vector<double> t_auth2, t_test2;
    std::vector<double> t_auth3i, t_auth3j, t_test3;
    std::vector<double> t_auth4, t_test4;

    for (int i = 0; i < N; i++)
    {
        MasterSecretKey tmp;
        auto t0 = high_resolution_clock::now();
        scheme.setup(tmp);
        t_setup.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        element_clear(tmp.s1); element_clear(tmp.s2);
    }

    for (int i = 0; i < N; i++)
    {
        DecryptionKey dk;
        auto t0 = high_resolution_clock::now();
        scheme.extract(id_alice, msk, dk);
        t_extract.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        element_clear(dk.dk1); element_clear(dk.dk2);
    }

    std::vector<Ciphertext> ctxts(N + 1);
    for (int i = 0; i <= N; i++)
    {
        auto t0 = high_resolution_clock::now();
        scheme.encrypt(id_alice, msg_orig, ctxts[i]);
        if (i < N)
            t_encrypt.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
    }

    for (int i = 0; i < N; i++)
    {
        uint8_t dec[MESSAGE_SPACE] = {};
        auto t0 = high_resolution_clock::now();
        scheme.decrypt(dk_alice, ctxts[i], dec);
        t_decrypt.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
    }

    // Type-1
    {
        std::vector<Trapdoor1> td1s(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth1(dk_alice, td1s[i]);
            if (i < N)
                t_auth1.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test1(ctxts[i], td1s[i], ctxts[i + 1], td1s[i + 1]);
            t_test1.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++) element_clear(td1s[i].td1);
    }

    // Type-2
    {
        std::vector<Trapdoor2> td2s(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth2(dk_alice, ctxts[i], td2s[i]);
            if (i < N)
                t_auth2.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test2(ctxts[i], td2s[i], ctxts[i + 1], td2s[i + 1]);
            t_test2.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++) element_clear(td2s[i].td2);
    }

    // Type-3
    {
        std::vector<Trapdoor3i> td3is(N + 1);
        std::vector<Trapdoor3j> td3js(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth3i(dk_alice, ctxts[i], td3is[i]);
            if (i < N)
                t_auth3i.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth3j(dk_alice, td3js[i]);
            if (i < N)
                t_auth3j.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test3(ctxts[i], td3is[i], ctxts[i + 1], td3js[i + 1]);
            t_test3.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++)
        {
            element_clear(td3is[i].td3);
            element_clear(td3js[i].td3);
        }
    }

    // Type-4
    {
        element_t gamma;
        element_init_Zr(gamma, scheme.pairing);
        element_random(gamma);

        std::vector<Trapdoor4> td4s(N + 1);
        for (int i = 0; i <= N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.auth4(dk_alice, ctxts[i], ctxts[(i + 1) % (N + 1)], gamma, td4s[i]);
            if (i < N)
                t_auth4.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i < N; i++)
        {
            auto t0 = high_resolution_clock::now();
            scheme.test4(ctxts[i], td4s[i], ctxts[i + 1], td4s[i + 1]);
            t_test4.push_back(duration<double, std::milli>(high_resolution_clock::now() - t0).count());
        }
        for (int i = 0; i <= N; i++)
        {
            element_clear(td4s[i].TD1);
            element_clear(td4s[i].TD2);
        }
        element_clear(gamma);
    }

    std::cout << "Setup   : " << avg(t_setup)   << " ms\n";
    std::cout << "Extract : " << avg(t_extract) << " ms\n";
    std::cout << "Encrypt : " << avg(t_encrypt) << " ms\n";
    std::cout << "Decrypt : " << avg(t_decrypt) << " ms\n";
    std::cout << "Auth1   : " << avg(t_auth1)   << " ms\n";
    std::cout << "Test1   : " << avg(t_test1)   << " ms\n";
    std::cout << "Auth2   : " << avg(t_auth2)   << " ms\n";
    std::cout << "Test2   : " << avg(t_test2)   << " ms\n";
    std::cout << "Auth3i  : " << avg(t_auth3i)  << " ms\n";
    std::cout << "Auth3j  : " << avg(t_auth3j)  << " ms\n";
    std::cout << "Test3   : " << avg(t_test3)   << " ms\n";
    std::cout << "Auth4   : " << avg(t_auth4)   << " ms\n";
    std::cout << "Test4   : " << avg(t_test4)   << " ms\n";

    for (int i = 0; i <= N; i++)
    {
        element_clear(ctxts[i].C1);
        element_clear(ctxts[i].C2);
        element_clear(ctxts[i].C3);
    }
    element_clear(dk_alice.dk1); element_clear(dk_alice.dk2);
    element_clear(dk_bob.dk1);   element_clear(dk_bob.dk2);
    element_clear(msk.s1);       element_clear(msk.s2);
}

// ── main ──────────────────────────────────────────────────────────────────────

static void print_usage(const char *prog)
{
    std::cerr << "Usage: " << prog
              << " -p <param_file> [-n iterations]\n"
              << "  -p  PBC pairing parameter file (required)\n"
              << "  -n  number of benchmark iterations (default: 10)\n";
}

int main(int argc, char *argv[])
{
    int N = 10;
    std::string param_file = "";

    for (int i = 1; i < argc; i++)
    {
        std::string a(argv[i]);
        if      (a == "-n" && i + 1 < argc) { N          = std::atoi(argv[++i]); }
        else if (a == "-p" && i + 1 < argc) { param_file = argv[++i]; }
        else { print_usage(argv[0]); return 1; }
    }

    if (param_file.empty())
    {
        std::cerr << "Error: -p <param_file> is required.\n\n";
        print_usage(argv[0]);
        return 1;
    }

    std::ifstream ifs(param_file);
    if (!ifs.is_open())
    {
        std::cerr << "Error: cannot open parameter file: " << param_file << "\n";
        return 1;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    const std::string param_str = oss.str();

    run_eze20(N, param_str);
    run_ibeaet(N, param_str);

    return 0;
}