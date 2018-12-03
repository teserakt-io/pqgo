//  params.h
//  2018-06-26  Markku-Juhani O. Saarinen <mjos@iki.fi>

#pragma once

#include <stddef.h>
#include <stdint.h>

#define R5ND_3KEMb

// Experimental non-ternary version

#ifdef R5ND_EXPR
#define PARAMS_ND 786
// Variance is (378 + 84*2^2 + 8*3^2)/786 = 1
#define PARAMS_H1 378
#define PARAMS_H2 84
#define PARAMS_H3 8
#define PARAMS_H (PARAMS_H1 + PARAMS_H2 + PARAMS_H3)
#define PARAMS_Q_BITS 16
#define PARAMS_P_BITS 8
#define PARAMS_T_BITS 6
#define PARAMS_SS_SIZE 24
#define PARAMS_XE 103
#define ROUND5_ALGNAME "Round5 R5ND_EXPR"
#endif

// parameter sets defined here

#ifdef R5ND_1KEMb
#define NOFO_CPA
#define PARAMS_ND 490
#define PARAMS_H 162
#define PARAMS_Q_BITS 10
#define PARAMS_P_BITS 7
#define PARAMS_T_BITS 4
#define PARAMS_SS_SIZE 16
#define PARAMS_XE 91
#define ROUND5_ALGNAME "Round5 R5ND_1KEMb"
#endif

#ifdef R5ND_3KEMb
#define NOFO_CPA
#define PARAMS_ND 756
#define PARAMS_H 242
#define PARAMS_Q_BITS 12
#define PARAMS_P_BITS 8
#define PARAMS_T_BITS 2
#define PARAMS_SS_SIZE 24
#define PARAMS_XE 103
#define ROUND5_ALGNAME "Round5 R5ND_3KEMb"
#endif

#ifdef R5ND_5KEMb
#define NOFO_CPA
#define PARAMS_ND 940
#define PARAMS_H 414
#define PARAMS_Q_BITS 12
#define PARAMS_P_BITS 8
#define PARAMS_T_BITS 3
#define PARAMS_SS_SIZE 32
#define PARAMS_XE 121
#define ROUND5_ALGNAME "Round5 R5ND_5KEMb"
#endif

#ifdef R5ND_1PKEb
#define PARAMS_ND 522
#define PARAMS_H 208
#define PARAMS_Q_BITS 13
#define PARAMS_P_BITS 8
#define PARAMS_T_BITS 3
#define PARAMS_SS_SIZE 16
#define PARAMS_XE 91
#define ROUND5_ALGNAME "Round5 R5ND_1PKEb"
#endif

#ifdef R5ND_3PKEb
#define PARAMS_ND 756
#define PARAMS_H 242
#define PARAMS_Q_BITS 12
#define PARAMS_P_BITS 8
#define PARAMS_T_BITS 3
#define PARAMS_SS_SIZE 24
#define PARAMS_XE 103
#define ROUND5_ALGNAME "Round5 R5ND_3PKEb"
#endif

#ifdef R5ND_5PKEb
#define PARAMS_ND 940
#define PARAMS_H 406
#define PARAMS_Q_BITS 12
#define PARAMS_P_BITS 8
#define PARAMS_T_BITS 4
#define PARAMS_SS_SIZE 32
#define PARAMS_XE 121
#define ROUND5_ALGNAME "Round5 R5ND_5PKEb"
#endif

#ifndef ROUND5_ALGNAME
#error You must define one of: R5ND_1KEMb R5ND_1PKEb R5ND_3KEMb R5ND_3PKEb R5ND_5KEMb R5ND_5PKEb.
#endif

// appropriate types
typedef uint16_t modq_t;
#if (PARAMS_P_BITS <= 8)
typedef uint8_t modp_t;
#else
typedef uint16_t modp_t;
#endif
typedef uint8_t modt_t;

// padding space for unrolled loop
#ifdef CM_CACHE
#define PARAMS_MUL_PAD 1
#else
#define PARAMS_MUL_PAD 4
#endif /* CM_CACHE */

// derive internal parameters
#ifndef BITS_TO_BYTES
#define BITS_TO_BYTES(x) (((x) + 7) / 8)
#endif

#define PARAMS_Q (1 << PARAMS_Q_BITS)
#define PARAMS_Q_MASK (PARAMS_Q - 1)
#define PARAMS_P_MASK ((1 << PARAMS_P_BITS) - 1)
#define PARAMS_MU (8 * PARAMS_SS_SIZE + PARAMS_XE)
#define PARAMS_XE_SIZE BITS_TO_BYTES (PARAMS_XE)
#define PARAMS_NDP_SIZE BITS_TO_BYTES (PARAMS_ND *PARAMS_P_BITS)
#define PARAMS_MUT_SIZE BITS_TO_BYTES (PARAMS_MU *PARAMS_T_BITS)
#define PARAMS_RS_DIV (0x10000 / PARAMS_ND)
#define PARAMS_RS_LIM (PARAMS_ND * PARAMS_RS_DIV)

#define PARAMS_PK_SIZE (PARAMS_SS_SIZE + PARAMS_NDP_SIZE)
#define PARAMS_SK_SIZE PARAMS_SS_SIZE
#define PARAMS_CT_SIZE (PARAMS_NDP_SIZE + PARAMS_MUT_SIZE)

// Derive the NIST parameters

// NOFO_CPA = no Fujisaki-Okamoto -> CPA
#ifdef NOFO_CPA

// CPA Variant
#define ROUND5_SECRETKEYBYTES PARAMS_SK_SIZE
#define ROUND5_PUBLICKEYBYTES PARAMS_PK_SIZE
#define ROUND5_BYTES PARAMS_SS_SIZE
#define ROUND5_CIPHERTEXTBYTES PARAMS_CT_SIZE

#else /* NOFO_CPA */

// CCA Variant
#define ROUND5_SECRETKEYBYTES (PARAMS_SK_SIZE + PARAMS_SS_SIZE + PARAMS_PK_SIZE)
#define ROUND5_PUBLICKEYBYTES PARAMS_PK_SIZE
#define ROUND5_BYTES PARAMS_SS_SIZE
#define ROUND5_CIPHERTEXTBYTES (PARAMS_CT_SIZE + PARAMS_SS_SIZE)

#endif /* NOFO_CPA */
