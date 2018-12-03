#ifndef API_H
#define API_H

//#ifndef MODE
#define MODE 2
//#endif

/*
#if MODE == 0
#define DILITHIUM_PUBLICKEYBYTES 896U
#define DILITHIUM_SECRETKEYBYTES 2096U
#define DILITHIUM_BYTES 1387U

#elif MODE == 1
#define DILITHIUM_PUBLICKEYBYTES 1184U
#define DILITHIUM_SECRETKEYBYTES 2800U
#define DILITHIUM_BYTES 2044U

#elif MODE == 2
*/

#define DILITHIUM_PUBLICKEYBYTES 1472U
#define DILITHIUM_SECRETKEYBYTES 3504U
#define DILITHIUM_BYTES 2701U

/*
#elif MODE == 3
#define DILITHIUM_PUBLICKEYBYTES 1760U
#define DILITHIUM_SECRETKEYBYTES 3856U
#define DILITHIUM_BYTES 3366U

#endif
*/

#define DILITHIUM_ALGNAME "Dilithium"

int dilithium_sign_keypair_cgo (char *pk, char *sk, char *seed);
int dilithium_sign_keypair (unsigned char *pk, unsigned char *sk, unsigned char *seed);

int dilithium_sign (unsigned char *sm,
                    unsigned long long *smlen,
                    const unsigned char *msg,
                    unsigned long long len,
                    const unsigned char *sk);

int dilithium_sign_open (unsigned char *m,
                         unsigned long long *mlen,
                         const unsigned char *sm,
                         unsigned long long smlen,
                         const unsigned char *pk);

#endif
