#pragma once

#include "params.h"
#include "poly.h"
#include "polyvec.h"

void expand_mat (polyvecl mat[K], const unsigned char rho[SEEDBYTES]);
void challenge (poly *c, const unsigned char mu[CRHBYTES], const polyveck *w1);

int dilithium_sign_keypair (unsigned char *pk, unsigned char *sk, unsigned char *seed);

int dilithium_sign_keypair_go (char *pk, char *sk, char *seed);

int dilithium_sign (unsigned char *sm,
                    unsigned long long *smlen,
                    const unsigned char *msg,
                    unsigned long long len,
                    const unsigned char *sk);

int dilithium_sign_cgo (char *sm, char *m, unsigned long long mlen, char *sk);

int dilithium_sign_open (unsigned char *m,
                         unsigned long long *mlen,
                         const unsigned char *sm,
                         unsigned long long smlen,
                         const unsigned char *pk);
