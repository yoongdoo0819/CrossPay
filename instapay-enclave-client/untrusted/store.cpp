#include "app.h"
#include "enclave_u.h"

#include <stdio.h>
#include <string.h>


void ecall_store_account_data_w(char *keyfile)
{
    ecall_store_account_data(global_eid, keyfile);
}


void ocall_remove_key_file(char *keyfile)
{
    if(remove(keyfile) != 0)
        printf("error deleting file\n");
    else
        printf("removed file successfully\n");
}


void ocall_store_sealed_seckey(char *keyfile, unsigned char *sealed_seckey)
{
    FILE *fp = fopen(keyfile, "ab");
    int count;

    count = fwrite(sealed_seckey, sizeof(unsigned char), 592, fp);
    printf("write %d bytes to %s\n", count, keyfile);

    fclose(fp);

    return;
}


void ecall_store_channel_data_w(char *chfile)
{
    ecall_store_channel_data(global_eid, chfile);
}


void ocall_remove_channel_file(char *chfile)
{
    if(remove(chfile) != 0)
        printf("error deleting file\n");
    else
        printf("removed file successfully\n");
}


void ocall_store_sealed_channel_data(char *chfile, unsigned char *sealed_channel_data)
{
    FILE *fp = fopen(chfile, "ab");
    int count;

    count = fwrite(sealed_channel_data, sizeof(unsigned char), 632, fp);
    printf("write %d bytes to %s\n", count, chfile);

    fclose(fp);

    return;
}
