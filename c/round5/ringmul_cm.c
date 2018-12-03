//  ringmul_cm.c
//  2018-06-26  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  This version includes cache timing attack countermeasures.

#ifdef CM_CACHE

#include <string.h>

#include "api.h"
#include "ringmul.h"
#include "xof_hash.h"

#define PROBEVEC64 ((PARAMS_ND + 63) / 64)

// Cache-resistant "occupancy probe". Tests and "occupies" a single bit at x.
// Return value zero (false) indicates the the slot was originally empty.

static int probe_cm (uint64_t *v, int x) {
    int i;
    uint64_t a, b, c, y, z;

    // construct the selector
    y = (1llu) << (x & 0x3F); // low bits of index

#if 0
    z = (1llu) << (x >> 6);                 // high bits of index
#else
    z = 1llu; // no constant-time 64-bit shift
    a = -((x >> 6) & 1);
    z = ((z << 1) & a) ^ (z & ~a);
    a = -((x >> 7) & 1);
    z = ((z << 2) & a) ^ (z & ~a);
    a = -((x >> 8) & 1);
    z = ((z << 4) & a) ^ (z & ~a);
    a = -((x >> 9) & 1);
    z = ((z << 8) & a) ^ (z & ~a);
    a = -((x >> 10) & 1); // can handle up to n=d=2048
    z = ((z << 16) & a) ^ (z & ~a);
#endif

    c = 0;
    for (i = 0; i < PROBEVEC64; i++) { // always scan through all
        a = v[i];
        b = a | (y & (-(z & 1))); // set bit
        c |= a ^ b;               // mask for change
        v[i] = b;
        z >>= 1;
    }

    // final comparison doesn't need to be constant time
    return c == 0; // return true if was occupied
}

// create a sparse ternary vector from a seed

void create_spter_idx (uint16_t idx[PARAMS_H / 2][2], const uint8_t *seed, const size_t seed_size) {
    size_t i;
    uint16_t x;
    uint64_t v[PROBEVEC64];
    XOF_ctx xof;

    memset (v, 0, sizeof (v));
    XOF_absorb (&xof, seed, seed_size); // initialize with seed

    for (i = 0; i < PARAMS_H; i++) {
        do {
            do {
                XOF_squeeze (&xof, &x, 2);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
                x = ((x << 8) ^ (x >> 8)) & 0xFFFF;
#endif
            } while (x >= PARAMS_RS_LIM);
            x /= PARAMS_RS_DIV;
        } while (probe_cm (v, x));
        idx[i >> 1][i & 1] = x; // addition / subtract index
    }
}

// multiplication mod q, result length n

void ringmul_q (modq_t d[PARAMS_ND + PARAMS_MUL_PAD],
                const modq_t a[PARAMS_ND],
                const uint16_t idx[PARAMS_H / 2][2]) {
    size_t i, j, k;
    modq_t t, p[PARAMS_ND + 1];

    memcpy (p, a, PARAMS_ND * sizeof (modq_t));
    p[PARAMS_ND] = 0;
    memset (d, 0, (PARAMS_ND + 1) * sizeof (modq_t));

    for (i = 0; i < PARAMS_H / 2; i++) {

        // non-ternary distributions
#ifdef PARAMS_H1
        if (i == PARAMS_H1 / 2
#ifdef PARAMS_H2
            || i == (PARAMS_H1 + PARAMS_H2) / 2
#endif
#ifdef PARAMS_H3
        // Redundant if PARAMS_H4 == 0
        // || i == (PARAMS_H1 + PARAMS_H2 + PARAMS_H3) / 2
#endif
        ) {
            // get the next multiple of a
            for (j = 0; j < PARAMS_ND; j++) {
                p[j] += a[j];
            }
        }
#endif /* PARAMS_H1 */

        k = idx[i][0]; // positive coefficient
        for (j = 0; k < PARAMS_ND;) d[j++] += p[k++];
        j++;
        for (k = 0; j <= PARAMS_ND;) d[j++] += p[k++];

        k = idx[i][1]; // negative coefficient
        for (j = 0; k < PARAMS_ND;) d[j++] -= p[k++];
        j++;
        for (k = 0; j <= PARAMS_ND;) d[j++] -= p[k++];
    }

    t = d[PARAMS_ND]; // reduce mod Phi
    for (i = 0; i < PARAMS_ND; i++) {
        d[i] -= t;
    }
}

// multiplication mod p, result length mu

void ringmul_p (modp_t d[PARAMS_MU + PARAMS_MUL_PAD],
                const modp_t a[PARAMS_ND],
                const uint16_t idx[PARAMS_H / 2][2]) {
    size_t i, j, k;
    modp_t p[PARAMS_ND + 1], e[PARAMS_ND];

    memcpy (p, a, PARAMS_ND * sizeof (modp_t));
    p[PARAMS_ND] = 0;

    memset (e, 0, PARAMS_ND * sizeof (modp_t));

    for (i = 0; i < PARAMS_H / 2; i++) {

        // non-ternary distributions
#ifdef PARAMS_H1
        if (i == PARAMS_H1 / 2
#ifdef PARAMS_H2
            || i == (PARAMS_H1 + PARAMS_H2) / 2
#endif
#ifdef PARAMS_H3
        // Redundant if PARAMS_H4 == 0
        // || i == (PARAMS_H1 + PARAMS_H2 + PARAMS_H3) / 2
#endif
        ) {
            // get the next multiple of a
            for (j = 0; j < PARAMS_ND; j++) {
                p[j] += a[j];
            }
        }
#endif /* PARAMS_H1 */

        k = idx[i][0]; // positive coefficient
        for (j = 0; k < PARAMS_ND;) e[j++] += p[k++];
        j++;
        for (k = 0; j < PARAMS_ND;) e[j++] += p[k++];

        k = idx[i][1]; // negative coefficient
        for (j = 0; k < PARAMS_ND;) e[j++] -= p[k++];
        j++;
        for (k = 0; j < PARAMS_ND;) e[j++] -= p[k++];
    }

    // copy the first part to caller
    memcpy (d, e, PARAMS_MU * sizeof (modp_t));
}

#endif /* CM_CACHE */
