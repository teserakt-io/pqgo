#pragma once

#include "kyber_poly.h"
#include "params.h"

typedef struct {
    kyber_poly vec[KYBER_K];
} kyber_polyvec;

void kyber_polyvec_compress (unsigned char *r, const kyber_polyvec *a);
void kyber_polyvec_decompress (kyber_polyvec *r, const unsigned char *a);

void kyber_polyvec_tobytes (unsigned char *r, const kyber_polyvec *a);
void kyber_polyvec_frombytes (kyber_polyvec *r, const unsigned char *a);

void kyber_polyvec_ntt (kyber_polyvec *r);
void kyber_polyvec_invntt (kyber_polyvec *r);

void kyber_polyvec_pointwise_acc (kyber_poly *r, const kyber_polyvec *a, const kyber_polyvec *b);

void kyber_polyvec_add (kyber_polyvec *r, const kyber_polyvec *a, const kyber_polyvec *b);
