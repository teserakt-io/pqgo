//  rng.h
//  2018-04-28  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef __RNG_H__
#define __RNG_H__

#define RNG_SUCCESS 0
#define RNG_BAD_MAXLEN -1
#define RNG_BAD_OUTBUF -2
#define RNG_BAD_REQ_LEN -3

void randombytes_init (unsigned char *entropy_input,
                       unsigned char *personalization_string,
                       int security_strength);

int randombytes (unsigned char *x, unsigned long long xlen);

#endif /* __RNG_H__ */
