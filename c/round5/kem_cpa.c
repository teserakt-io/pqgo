//  kem_cpa.c
//  2018-06-17  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  CPA Versions of KEM functionality

#include "api.h"

#ifdef NOFO_CPA

#include <stdlib.h>
#include <string.h>

#include "../randombytes/rng.h"
#include "../randombytes/xof_hash.h"
#include "encrypt.h"

// CPA-KEM KeyGen()

int round5_kem_keypair (char *pk, char *sk) {
    generate_keypair ((uint8_t *)pk, (uint8_t *)sk);

    return 0;
}

/* TESERAKT */
int round5_kem_keypair_cgo (char *pk, char *sk, const char *entropy) {
    randombytes_init ((unsigned char *)entropy, NULL, 0);
    generate_keypair ((uint8_t *)pk, (uint8_t *)sk);

    return 0;
}

// CPA-KEM Encaps()

int round5_kem_enc (uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t hash_input[PARAMS_SS_SIZE + ROUND5_CIPHERTEXTBYTES];
    uint8_t m[PARAMS_SS_SIZE];
    uint8_t rho[PARAMS_SS_SIZE];

    // Generate a random m
    randombytes (m, PARAMS_SS_SIZE);
    randombytes (rho, PARAMS_SS_SIZE);
    encrypt_rho (ct, m, rho, pk);

    // K = H(m, c)
    memcpy (hash_input, m, PARAMS_SS_SIZE);
    memcpy (hash_input + PARAMS_SS_SIZE, ct, ROUND5_CIPHERTEXTBYTES);
    XOF_hash (ss, hash_input, PARAMS_SS_SIZE + ROUND5_CIPHERTEXTBYTES, PARAMS_SS_SIZE);

    return 0;
}

/* TESERAKT */
int round5_kem_enc_cgo (char *ct, char *ss, const char *pk, const char *entropy) {
    randombytes_init ((unsigned char *)entropy, NULL, 0);
    return round5_kem_enc ((unsigned char *)ct, (unsigned char *)ss,
                           (const unsigned char *)pk);
}


// CPA-KEM Decaps()

int round5_kem_dec (uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t hash_input[PARAMS_SS_SIZE + ROUND5_CIPHERTEXTBYTES];
    uint8_t m[PARAMS_SS_SIZE];

    // Decrypt m
    decrypt (m, ct, sk);

    // K = H(m, c)
    memcpy (hash_input, m, PARAMS_SS_SIZE);
    memcpy (hash_input + PARAMS_SS_SIZE, ct, ROUND5_CIPHERTEXTBYTES);
    XOF_hash (ss, hash_input, PARAMS_SS_SIZE + ROUND5_CIPHERTEXTBYTES, PARAMS_SS_SIZE);

    return 0;
}

/* TESERAKT */
int round5_kem_dec_cgo (char *ss, const char *ct, const char *sk) {
    return round5_kem_dec ((unsigned char *)ss, (const unsigned char *)ct,
                           (const unsigned char *)sk);
}

#endif /* NOFO_CPA */
