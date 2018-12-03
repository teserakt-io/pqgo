#include "indcpa.h"
#include "../fips202/fips202.h"
#include "../randombytes/rng.h"
#include "kyber_ntt.h"
#include "kyber_poly.h"
#include "kyber_polyvec.h"
#include <string.h>

/*************************************************
 * Name:        kyber_pack_pk
 *
 * Description: Serialize the public key as concatenation of the
 *              compressed and serialized vector of polynomials pk
 *              and the public seed used to generate the matrix A.
 *
 * Arguments:   unsigned char *r:          pointer to the output serialized
 *public key const kyber_poly *pk:            pointer to the input public-key
 *polynomial const unsigned char *seed: pointer to the input public seed
 **************************************************/
static void
kyber_pack_pk (unsigned char *r, const kyber_polyvec *pk, const unsigned char *seed) {
    int i;
    kyber_polyvec_compress (r, pk);
    for (i = 0; i < KYBER_SYMBYTES; i++)
        r[i + KYBER_POLYVECCOMPRESSEDBYTES] = seed[i];
}

/*************************************************
 * Name:        kyber_unpack_pk
 *
 * Description: De-serialize and decompress public key from a byte array;
 *              approximate inverse of kyber_pack_pk
 *
 * Arguments:   - kyber_polyvec *pk:                   pointer to output public-key vector of polynomials
 *              - unsigned char *seed:           pointer to output seed to generate matrix A
 *              - const unsigned char *packedpk: pointer to input serialized public key
 **************************************************/
static void
kyber_unpack_pk (kyber_polyvec *pk, unsigned char *seed, const unsigned char *packedpk) {
    int i;
    kyber_polyvec_decompress (pk, packedpk);

    for (i = 0; i < KYBER_SYMBYTES; i++)
        seed[i] = packedpk[i + KYBER_POLYVECCOMPRESSEDBYTES];
}

/*************************************************
 * Name:        kyber_pack_ciphertext
 *
 * Description: Serialize the ciphertext as concatenation of the
 *              compressed and serialized vector of polynomials b
 *              and the compressed and serialized polynomial v
 *
 * Arguments:   unsigned char *r:          pointer to the output serialized
 *ciphertext const kyber_poly *pk:            pointer to the input vector of
 *polynomials b const unsigned char *seed: pointer to the input polynomial v
 **************************************************/
static void
kyber_pack_ciphertext (unsigned char *r, const kyber_polyvec *b, const kyber_poly *v) {
    kyber_polyvec_compress (r, b);
    kyber_poly_compress (r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
 * Name:        kyber_unpack_ciphertext
 *
 * Description: De-serialize and decompress ciphertext from a byte array;
 *              approximate inverse of kyber_pack_ciphertext
 *
 * Arguments:   - kyber_polyvec *b:             pointer to the output vector of polynomials b
 *              - kyber_poly *v:                pointer to the output polynomial v
 *              - const unsigned char *c: pointer to the input serialized ciphertext
 **************************************************/
static void
kyber_unpack_ciphertext (kyber_polyvec *b, kyber_poly *v, const unsigned char *c) {
    kyber_polyvec_decompress (b, c);
    kyber_poly_decompress (v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
 * Name:        kyber_pack_sk
 *
 * Description: Serialize the secret key
 *
 * Arguments:   - unsigned char *r:  pointer to output serialized secret key
 *              - const kyber_polyvec *sk: pointer to input vector of polynomials (secret key)
 **************************************************/
static void kyber_pack_sk (unsigned char *r, const kyber_polyvec *sk) {
    kyber_polyvec_tobytes (r, sk);
}

/*************************************************
 * Name:        kyber_unpack_sk
 *
 * Description: De-serialize the secret key;
 *              inverse of kyber_pack_sk
 *
 * Arguments:   - kyber_polyvec *sk:                   pointer to output vector of polynomials (secret key)
 *              - const unsigned char *packedsk: pointer to input serialized secret key
 **************************************************/
static void kyber_unpack_sk (kyber_polyvec *sk, const unsigned char *packedsk) {
    kyber_polyvec_frombytes (sk, packedsk);
}

#define gen_a(A, B) gen_matrix (A, B, 0)
#define gen_at(A, B) gen_matrix (A, B, 1)

/*************************************************
 * Name:        gen_matrix
 *
 * Description: Deterministically generate matrix A (or the transpose of A)
 *              from a seed. Entries of the matrix are polynomials that look
 *              uniformly random. Performs rejection sampling on output of
 *              SHAKE-128
 *
 * Arguments:   - kyber_polyvec *a:                pointer to ouptput matrix A
 *              - const unsigned char *seed: pointer to input seed
 *              - int transposed:            boolean deciding whether A or A^T is generated
 **************************************************/
void gen_matrix (kyber_polyvec *a, const unsigned char *seed, int transposed) // Not static for benchmarking
{
    unsigned int pos = 0, ctr;
    uint16_t val;
    unsigned int nblocks;
    const unsigned int maxnblocks = 4;
    uint8_t buf[SHAKE128_RATE * maxnblocks];
    int i, j;
    uint64_t state[25]; // SHAKE state
    unsigned char extseed[KYBER_SYMBYTES + 2];

    for (i = 0; i < KYBER_SYMBYTES; i++) extseed[i] = seed[i];


    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_K; j++) {
            ctr = pos = 0;
            nblocks = maxnblocks;
            if (transposed) {
                extseed[KYBER_SYMBYTES] = i;
                extseed[KYBER_SYMBYTES + 1] = j;
            } else {
                extseed[KYBER_SYMBYTES] = j;
                extseed[KYBER_SYMBYTES + 1] = i;
            }

            shake128_absorb (state, extseed, KYBER_SYMBYTES + 2);
            shake128_squeezeblocks (buf, nblocks, state);

            while (ctr < KYBER_N) {
                val = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
                if (val < KYBER_Q) {
                    a[i].vec[j].coeffs[ctr++] = val;
                }
                pos += 2;

                if (pos > SHAKE128_RATE * nblocks - 2) {
                    nblocks = 1;
                    shake128_squeezeblocks (buf, nblocks, state);
                    pos = 0;
                }
            }
        }
    }
}


/*************************************************
 * Name:        indcpa_keypair
 *
 * Description: Generates public and private key for the CPA-secure
 *              public-key encryption scheme underlying Kyber
 *
 * Arguments:   - unsigned char *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
 **************************************************/
void indcpa_keypair (unsigned char *pk, unsigned char *sk) {
    kyber_polyvec a[KYBER_K], e, pkpv, skpv;
    unsigned char buf[KYBER_SYMBYTES + KYBER_SYMBYTES];
    unsigned char *publicseed = buf;
    unsigned char *noiseseed = buf + KYBER_SYMBYTES;
    int i;
    unsigned char nonce = 0;

    randombytes (buf, KYBER_SYMBYTES);
    sha3_512 (buf, buf, KYBER_SYMBYTES);

    gen_a (a, publicseed);

    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise (skpv.vec + i, noiseseed, nonce++);

    kyber_polyvec_ntt (&skpv);

    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise (e.vec + i, noiseseed, nonce++);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++)
        kyber_polyvec_pointwise_acc (&pkpv.vec[i], &skpv, a + i);

    kyber_polyvec_invntt (&pkpv);
    kyber_polyvec_add (&pkpv, &pkpv, &e);

    kyber_pack_sk (sk, &skpv);
    kyber_pack_pk (pk, &pkpv, publicseed);
}


/*************************************************
 * Name:        indcpa_enc
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - unsigned char *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
 *              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
 *              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
 *              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
 *                                           to deterministically generate all randomness
 **************************************************/
void indcpa_enc (unsigned char *c,
                 const unsigned char *m,
                 const unsigned char *pk,
                 const unsigned char *coins) {
    kyber_polyvec sp, pkpv, ep, at[KYBER_K], bp;
    kyber_poly v, k, epp;
    unsigned char seed[KYBER_SYMBYTES];
    int i;
    unsigned char nonce = 0;


    kyber_unpack_pk (&pkpv, seed, pk);

    kyber_poly_frommsg (&k, m);

    kyber_polyvec_ntt (&pkpv);

    gen_at (at, seed);

    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise (sp.vec + i, coins, nonce++);

    kyber_polyvec_ntt (&sp);

    for (i = 0; i < KYBER_K; i++)
        kyber_poly_getnoise (ep.vec + i, coins, nonce++);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++)
        kyber_polyvec_pointwise_acc (&bp.vec[i], &sp, at + i);

    kyber_polyvec_invntt (&bp);
    kyber_polyvec_add (&bp, &bp, &ep);

    kyber_polyvec_pointwise_acc (&v, &pkpv, &sp);
    kyber_poly_invntt (&v);

    kyber_poly_getnoise (&epp, coins, nonce++);

    kyber_poly_add (&v, &v, &epp);
    kyber_poly_add (&v, &v, &k);

    kyber_pack_ciphertext (c, &bp, &v);
}

/*************************************************
 * Name:        indcpa_dec
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - unsigned char *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
 *              - const unsigned char *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
 *              - const unsigned char *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
 **************************************************/
void indcpa_dec (unsigned char *m, const unsigned char *c, const unsigned char *sk) {
    kyber_polyvec bp, skpv;
    kyber_poly v, mp;

    kyber_unpack_ciphertext (&bp, &v, c);
    kyber_unpack_sk (&skpv, sk);

    kyber_polyvec_ntt (&bp);

    kyber_polyvec_pointwise_acc (&mp, &skpv, &bp);
    kyber_poly_invntt (&mp);

    kyber_poly_sub (&mp, &mp, &v);

    kyber_poly_tomsg (m, &mp);
}
