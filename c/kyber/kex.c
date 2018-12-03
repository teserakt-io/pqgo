#include "kex.h"
#include "../fips202/fips202.h"
#include "verify.h"

void kyber_uake_initA (u8 *send, u8 *tk, u8 *sk, const u8 *pkb) {
    kyber_kem_keypair (send, sk);
    kyber_kem_enc (send + KYBER_PUBLICKEYBYTES, tk, pkb);
}

void kyber_uake_sharedB (u8 *send, u8 *k, const u8 *recv, const u8 *skb) {
    unsigned char buf[2 * KYBER_SYMBYTES];
    kyber_kem_enc (send, buf, recv);
    kyber_kem_dec (buf + KYBER_SYMBYTES, recv + KYBER_PUBLICKEYBYTES, skb);
    shake256 (k, KYBER_SYMBYTES, buf, 2 * KYBER_SYMBYTES);
}

void kyber_uake_sharedA (u8 *k, const u8 *recv, const u8 *tk, const u8 *sk) {
    unsigned char buf[2 * KYBER_SYMBYTES];
    int i;
    kyber_kem_dec (buf, recv, sk);
    for (i = 0; i < KYBER_SYMBYTES; i++) buf[i + KYBER_SYMBYTES] = tk[i];
    shake256 (k, KYBER_SYMBYTES, buf, 2 * KYBER_SYMBYTES);
}


void kyber_ake_initA (u8 *send, u8 *tk, u8 *sk, const u8 *pkb) {
    kyber_kem_keypair (send, sk);
    kyber_kem_enc (send + KYBER_PUBLICKEYBYTES, tk, pkb);
}

void kyber_ake_sharedB (u8 *send, u8 *k, const u8 *recv, const u8 *skb, const u8 *pka) {
    unsigned char buf[3 * KYBER_SYMBYTES];
    kyber_kem_enc (send, buf, recv);
    kyber_kem_enc (send + KYBER_CIPHERTEXTBYTES, buf + KYBER_SYMBYTES, pka);
    kyber_kem_dec (buf + 2 * KYBER_SYMBYTES, recv + KYBER_PUBLICKEYBYTES, skb);
    shake256 (k, KYBER_SYMBYTES, buf, 3 * KYBER_SYMBYTES);
}

void kyber_ake_sharedA (u8 *k, const u8 *recv, const u8 *tk, const u8 *sk, const u8 *ska) {
    unsigned char buf[3 * KYBER_SYMBYTES];
    int i;
    kyber_kem_dec (buf, recv, sk);
    kyber_kem_dec (buf + KYBER_SYMBYTES, recv + KYBER_CIPHERTEXTBYTES, ska);
    for (i = 0; i < KYBER_SYMBYTES; i++) buf[i + 2 * KYBER_SYMBYTES] = tk[i];
    shake256 (k, KYBER_SYMBYTES, buf, 3 * KYBER_SYMBYTES);
}
