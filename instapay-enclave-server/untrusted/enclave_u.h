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

sgx_status_t ecall_accept_request(sgx_enclave_id_t eid, unsigned char* sender, unsigned char* receiver, unsigned int amount, unsigned int* payment_num);
sgx_status_t ecall_add_participant(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* addr);
sgx_status_t ecall_update_sentagr_list(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* addr);
sgx_status_t ecall_update_sentupt_list(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* addr);
sgx_status_t ecall_check_unanimity(sgx_enclave_id_t eid, unsigned int payment_num, int which_list, int* is_unanimous);
sgx_status_t ecall_update_payment_status_to_success(sgx_enclave_id_t eid, unsigned int payment_num);
sgx_status_t ecall_create_ag_req_msg(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int payment_size, unsigned int* channel_ids, int* amount, unsigned char* req_msg, unsigned char* req_sig);
sgx_status_t ecall_create_ud_req_msg(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int payment_size, unsigned int* channel_ids, int* amount, unsigned char* req_msg, unsigned char* req_sig);
sgx_status_t ecall_create_confirm_msg(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* confirm_msg, unsigned char* confirm_sig);
sgx_status_t ecall_verify_ag_res_msg(sgx_enclave_id_t eid, unsigned char* pubaddr, unsigned char* res_msg, unsigned char* res_sig, unsigned int* is_verified);
sgx_status_t ecall_verify_ud_res_msg(sgx_enclave_id_t eid, unsigned char* pubaddr, unsigned char* res_msg, unsigned char* res_sig, unsigned int* is_verified);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
