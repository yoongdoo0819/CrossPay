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

void ecall_accept_request(unsigned char* sender, unsigned char* receiver, unsigned int amount, unsigned int* payment_num);
void ecall_add_participant(unsigned int payment_num, unsigned char* addr);
void ecall_update_sentagr_list(unsigned int payment_num, unsigned char* addr);
void ecall_update_sentupt_list(unsigned int payment_num, unsigned char* addr);
void ecall_check_unanimity(unsigned int payment_num, int which_list, int* is_unanimous);
void ecall_update_payment_status_to_success(unsigned int payment_num);
void ecall_create_ag_req_msg(unsigned int payment_num, unsigned int payment_size, unsigned int* channel_ids, int* amount, unsigned char* req_msg, unsigned char* req_sig);
void ecall_create_ud_req_msg(unsigned int payment_num, unsigned int payment_size, unsigned int* channel_ids, int* amount, unsigned char* req_msg, unsigned char* req_sig);
void ecall_create_confirm_msg(unsigned int payment_num, unsigned char* confirm_msg, unsigned char* confirm_sig);
void ecall_verify_ag_res_msg(unsigned char* pubaddr, unsigned char* res_msg, unsigned char* res_sig, unsigned int* is_verified);
void ecall_verify_ud_res_msg(unsigned char* pubaddr, unsigned char* res_msg, unsigned char* res_sig, unsigned int* is_verified);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
