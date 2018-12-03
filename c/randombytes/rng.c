//  rng.c
//  2018-06-15  Markku-Juhani O. Saarinen <mjos@iki.fi>

#include "rng.h"
#include "xof_hash.h"

// state for randombytes

static XOF_ctx rng_xof;

void randombytes_init (unsigned char *entropy_input,
                       unsigned char *personalization_string,
                       int security_strength) {
    XOF_absorb (&rng_xof, entropy_input, 48);
}

int randombytes (unsigned char *x, unsigned long long xlen) {
    XOF_squeeze (&rng_xof, x, xlen);
    return 0;
}
