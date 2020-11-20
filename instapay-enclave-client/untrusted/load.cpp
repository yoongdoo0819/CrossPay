#include "app.h"
#include "enclave_u.h"

#include <stdio.h>
#include <string.h>


void ecall_load_account_data_w(char *keyfile)
{
    FILE *fp = fopen(keyfile, "rb");   // sealed log size = 592
    unsigned char sealed_seckey[600];
    int count;

    if(fp == NULL) return;

    while(1) {
        count = fread(sealed_seckey, sizeof(unsigned char), 592, fp);
        if(count < 592) break;
        printf("read %d bytes from ./data/key/a0\n", count);
        ecall_load_account_data(global_eid, sealed_seckey);
    }

    fclose(fp);
}


void ecall_load_channel_data_w(char *chfile)
{
    FILE *fp = fopen(chfile, "rb");   // sealed log size = 628
    unsigned char sealed_channel_data[700];
    int count;

    if(fp == NULL) return;

    while(1) {
        count = fread(sealed_channel_data, sizeof(unsigned char), 628, fp);
        if(count < 628) break;
        printf("read %d bytes from ./data/channel/c0\n", count);
        ecall_load_channel_data(global_eid, sealed_channel_data);
    }

    fclose(fp);
}