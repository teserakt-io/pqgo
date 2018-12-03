#pragma once

#include "params.h"

#define KYBER_K 3

#if (KYBER_K == 2)
#define KYBER_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define KYBER_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define KYBER_ALGNAME "Kyber1024"
#else
#error "KYBER_K must be in {2,3,4}"
#endif

int kyber_kem_keypair (unsigned char *pk, unsigned char *sk);

int kyber_kem_enc (unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int kyber_kem_dec (unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
