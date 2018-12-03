// program to verify Go's golden values

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include "api.h"

int main() {

    unsigned char sk[KYBER_SECRETKEYBYTES];
    unsigned char pk[KYBER_PUBLICKEYBYTES];
    unsigned char ct[KYBER_CIPHERTEXTBYTES];
    unsigned char ss[KYBER_SYMBYTES];
    unsigned char ent[48];
    int fd;

    memset(ent, 0x00, 48);

    kyber_kem_keypair_cgo(pk, sk, ent);

    fd = open("kyber_sk.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, sk, KYBER_SECRETKEYBYTES);
    close(fd);

    fd = open("kyber_pk.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, pk, KYBER_PUBLICKEYBYTES);
    close(fd);

    kyber_kem_enc_cgo(ct, ss, pk, ent);

    fd = open("kyber_ss.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, ss, KYBER_SYMBYTES);
    close(fd);

    return 0;
}