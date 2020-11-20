#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_REMOVE_KEY_FILE_DEFINED__
#define OCALL_REMOVE_KEY_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remove_key_file, (char* keyfile));
#endif
#ifndef OCALL_STORE_SEALED_SECKEY_DEFINED__
#define OCALL_STORE_SEALED_SECKEY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_store_sealed_seckey, (char* keyfile, unsigned char* sealed_seckey));
#endif
#ifndef OCALL_REMOVE_CHANNEL_FILE_DEFINED__
#define OCALL_REMOVE_CHANNEL_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remove_channel_file, (char* chfile));
#endif
#ifndef OCALL_STORE_SEALED_CHANNEL_DATA_DEFINED__
#define OCALL_STORE_SEALED_CHANNEL_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_store_sealed_channel_data, (char* chfile, unsigned char* sealed_seckey));
#endif

sgx_status_t ecall_preset_account(sgx_enclave_id_t eid, unsigned char* addr, unsigned char* seckey);
sgx_status_t ecall_preset_payment(sgx_enclave_id_t eid, unsigned int pn, unsigned int channel_id, int amount);
sgx_status_t ecall_create_account(sgx_enclave_id_t eid, unsigned char* generated_addr);
sgx_status_t ecall_create_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int deposit, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_onchain_payment(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int amount, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_pay(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int amount, int* is_success, unsigned char* original_msg, unsigned char* output);
sgx_status_t ecall_paid(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output);
sgx_status_t ecall_pay_accepted(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature);
sgx_status_t ecall_get_balance(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int* balance);
sgx_status_t ecall_get_channel_info(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* channel_info);
sgx_status_t ecall_close_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned int channel_id, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_eject(sgx_enclave_id_t eid, unsigned int nonce, unsigned int pn, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_get_num_open_channels(sgx_enclave_id_t eid, unsigned int* num_open_channels);
sgx_status_t ecall_get_open_channels(sgx_enclave_id_t eid, unsigned char* open_channels);
sgx_status_t ecall_get_num_closed_channels(sgx_enclave_id_t eid, unsigned int* num_closed_channels);
sgx_status_t ecall_get_closed_channels(sgx_enclave_id_t eid, unsigned char* closed_channels);
sgx_status_t ecall_get_num_public_addrs(sgx_enclave_id_t eid, unsigned int* num_public_addrs);
sgx_status_t ecall_get_public_addrs(sgx_enclave_id_t eid, unsigned char* public_addrs);
sgx_status_t ecall_test_func(sgx_enclave_id_t eid);
sgx_status_t ecall_receive_create_channel(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* owner, unsigned char* receiver, unsigned int deposit);
sgx_status_t ecall_receive_close_channel(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int owner_bal, unsigned int receiver_bal);
sgx_status_t ecall_go_pre_update(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output);
sgx_status_t ecall_go_post_update(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output);
sgx_status_t ecall_go_idle(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature);
sgx_status_t ecall_register_comminfo(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* ip, unsigned int ip_size, unsigned int port);
sgx_status_t ecall_store_account_data(sgx_enclave_id_t eid, char* keyfile);
sgx_status_t ecall_store_channel_data(sgx_enclave_id_t eid, char* chfile);
sgx_status_t ecall_load_account_data(sgx_enclave_id_t eid, unsigned char* sealed_seckey);
sgx_status_t ecall_load_channel_data(sgx_enclave_id_t eid, unsigned char* sealed_channel_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
