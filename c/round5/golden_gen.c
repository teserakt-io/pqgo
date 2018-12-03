// program to verify Go's golden values

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include "api.h"

int main() {

    unsigned char sk[ROUND5_SECRETKEYBYTES];
    unsigned char pk[ROUND5_PUBLICKEYBYTES];
    unsigned char ct[ROUND5_CIPHERTEXTBYTES];
    unsigned char ss[PARAMS_SS_SIZE];
    unsigned char ent[32];
    int fd;

    memset(ent, 0x00, 32);

    round5_kem_keypair_cgo(pk, sk, ent);

    fd = open("round5_sk.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, sk, ROUND5_SECRETKEYBYTES);
    close(fd);

    fd = open("round5_pk.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, pk, ROUND5_PUBLICKEYBYTES);
    close(fd);

    round5_kem_enc_cgo(ct, ss, pk, ent);

    fd = open("round5_ss.golden", O_CREAT | O_WRONLY, 0644);
    write(fd, ss, PARAMS_SS_SIZE);
    close(fd);

    return 0;
}