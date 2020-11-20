#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_preset_account(unsigned char* addr, unsigned char* seckey);
void ecall_preset_payment(unsigned int pn, unsigned int channel_id, int amount);
void ecall_create_account(unsigned char* generated_addr);
void ecall_create_channel(unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int deposit, unsigned char* signed_tx, unsigned int* signed_tx_len);
void ecall_onchain_payment(unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int amount, unsigned char* signed_tx, unsigned int* signed_tx_len);
void ecall_pay(unsigned int channel_id, unsigned int amount, int* is_success, unsigned char* original_msg, unsigned char* output);
void ecall_paid(unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output);
void ecall_pay_accepted(unsigned char* msg, unsigned char* signature);
void ecall_get_balance(unsigned int channel_id, unsigned int* balance);
void ecall_get_channel_info(unsigned int channel_id, unsigned char* channel_info);
void ecall_close_channel(unsigned int nonce, unsigned int channel_id, unsigned char* signed_tx, unsigned int* signed_tx_len);
void ecall_eject(unsigned int nonce, unsigned int pn, unsigned char* signed_tx, unsigned int* signed_tx_len);
void ecall_get_num_open_channels(unsigned int* num_open_channels);
void ecall_get_open_channels(unsigned char* open_channels);
void ecall_get_num_closed_channels(unsigned int* num_closed_channels);
void ecall_get_closed_channels(unsigned char* closed_channels);
void ecall_get_num_public_addrs(unsigned int* num_public_addrs);
void ecall_get_public_addrs(unsigned char* public_addrs);
void ecall_test_func(void);
void ecall_receive_create_channel(unsigned int channel_id, unsigned char* owner, unsigned char* receiver, unsigned int deposit);
void ecall_receive_close_channel(unsigned int channel_id, unsigned int owner_bal, unsigned int receiver_bal);
void ecall_go_pre_update(unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output);
void ecall_go_post_update(unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output);
void ecall_go_idle(unsigned char* msg, unsigned char* signature);
void ecall_register_comminfo(unsigned int channel_id, unsigned char* ip, unsigned int ip_size, unsigned int port);
void ecall_store_account_data(char* keyfile);
void ecall_store_channel_data(char* chfile);
void ecall_load_account_data(unsigned char* sealed_seckey);
void ecall_load_channel_data(unsigned char* sealed_channel_data);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_remove_key_file(char* keyfile);
sgx_status_t SGX_CDECL ocall_store_sealed_seckey(char* keyfile, unsigned char* sealed_seckey);
sgx_status_t SGX_CDECL ocall_remove_channel_file(char* chfile);
sgx_status_t SGX_CDECL ocall_store_sealed_channel_data(char* chfile, unsigned char* sealed_seckey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
