//  api.h
//  2018-06-30  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef _API_H_
#define _API_H_

#include "params.h"

/*
    This is the API defined by NIST for PQC KEMs.

    Public key:     unsigned char pk[ROUND5_PUBLICKEYBYTES];
    Secret key:     unsigned char sk[ROUND5_SECRETKEYBYTES];
    Ciphertext:     unsigned char ct[ROUND5_CIPHERTEXTBYTES];
    Shared secret:  unsigned char ss[ROUND5_BYTES];

    The functions always return 0. In case of decryption error the shared
    secrets from round5_kem_enc() and round5_kem_dec() simply won't match.
*/

// Key generation: (pk, sk) = KeyGen()

int round5_kem_keypair (char *pk, char *sk);

int round5_kem_keypair_entropy (char *pk, char *sk, const char *entropy);

// Encapsulate: (ct, ss) = Encaps(pk)

int round5_kem_enc (unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int round5_kem_enc_entropy (char *ct, char *ss, const char *pk, const char *entropy);


// Decapsulate: ss = Decaps(ct, sk)

int round5_kem_dec (unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

int round5_kem_dec_cgo (char *ss, const char *ct, const char *sk);

#endif /* _API_H_ */
