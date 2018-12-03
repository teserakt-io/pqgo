// program to verify Go's golden values

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include "api.h"

int main() {

    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char m[256 + DILITHIUM_BYTES];
    unsigned char sm[256 + DILITHIUM_BYTES];
    unsigned char ent[32];
    int fd;

    memset(ent, 0x00, 32);
    memset(m, 0x00, 256 + DILITHIUM_BYTES);

    dilithium_sign_keypair_cgo(pk, sk, ent);

    fd = open("dilithium_sk.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, sk, DILITHIUM_SECRETKEYBYTES);
    close(fd);

    fd = open("dilithium_pk.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, pk, DILITHIUM_PUBLICKEYBYTES);
    close(fd);

    dilithium_sign_cgo(sm, m, 256, sk);

    fd = open("dilithium_sm.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, sm, 256 + DILITHIUM_BYTES);
    close(fd);

    return 0;
}