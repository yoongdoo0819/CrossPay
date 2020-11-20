#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "app.h"
#include "enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    /* =============== test =============== */

    unsigned int nonce = 0;
    unsigned char *A = (unsigned char*)"78902c58006916201F65f52f7834e467877f0500";
    unsigned char *owner = (unsigned char*)"D03A2CC08755eC7D75887f0997195654b928893e";
    unsigned char *B = (unsigned char*)"0b4161ad4f49781a821c308d672e6c669139843c";
    unsigned int deposit = 8;

    // std::string signed_tx = ecall_new_channel(nonce, owner, receiver, deposit);
    ecall_preset_account_w(owner, (unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd"); // preset account

    /*
                     id: 2                   id: 3
        A(0x7890...) -----> owner(0xd03a...) -----> B(0x0b41...)
    */
    // ecall_receive_create_channel_w(2, A, owner, 5);
    // ecall_receive_create_channel_w(3, owner, B, 9);
    // printf("[BEFORE] CHANNEL 2 BALANCE: %d\n", ecall_get_balance_w(2));
    // printf("[BEFORE] CHANNEL 3 BALANCE: %d\n", ecall_get_balance_w(3));

    // unsigned int channel_id[2] = {2, 3};
    // int amount[2] = {4, -4};

    // ecall_go_pre_update_w(10, channel_id, amount, 2);
    // ecall_go_post_update_w(10, channel_id, amount, 2);
    // ecall_go_idle_w(10);

    // printf("[AFTER] CHANNEL 2 BALANCE: %d\n", ecall_get_balance_w(2));
    // printf("[AFTER] CHANNEL 3 BALANCE: %d\n", ecall_get_balance_w(3));

    /* loading channel information */

    //ecall_load_channel_data_w(9, 0, 0, owner, 88, 0, 80, 0, B, (unsigned char *)"127.0.0.3", 7878);
    //printf("CHANNEL 9 BALANCE: %d\n", ecall_get_balance_w(9));

    /* =============== test =============== */

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}