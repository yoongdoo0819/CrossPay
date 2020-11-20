#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_accept_request_t {
	unsigned char* ms_sender;
	unsigned char* ms_receiver;
	unsigned int ms_amount;
	unsigned int* ms_payment_num;
} ms_ecall_accept_request_t;

typedef struct ms_ecall_add_participant_t {
	unsigned int ms_payment_num;
	unsigned char* ms_addr;
} ms_ecall_add_participant_t;

typedef struct ms_ecall_update_sentagr_list_t {
	unsigned int ms_payment_num;
	unsigned char* ms_addr;
} ms_ecall_update_sentagr_list_t;

typedef struct ms_ecall_update_sentupt_list_t {
	unsigned int ms_payment_num;
	unsigned char* ms_addr;
} ms_ecall_update_sentupt_list_t;

typedef struct ms_ecall_check_unanimity_t {
	unsigned int ms_payment_num;
	int ms_which_list;
	int* ms_is_unanimous;
} ms_ecall_check_unanimity_t;

typedef struct ms_ecall_update_payment_status_to_success_t {
	unsigned int ms_payment_num;
} ms_ecall_update_payment_status_to_success_t;

typedef struct ms_ecall_create_ag_req_msg_t {
	unsigned int ms_payment_num;
	unsigned int ms_payment_size;
	unsigned int* ms_channel_ids;
	int* ms_amount;
	unsigned char* ms_req_msg;
	unsigned char* ms_req_sig;
} ms_ecall_create_ag_req_msg_t;

typedef struct ms_ecall_create_ud_req_msg_t {
	unsigned int ms_payment_num;
	unsigned int ms_payment_size;
	unsigned int* ms_channel_ids;
	int* ms_amount;
	unsigned char* ms_req_msg;
	unsigned char* ms_req_sig;
} ms_ecall_create_ud_req_msg_t;

typedef struct ms_ecall_create_confirm_msg_t {
	unsigned int ms_payment_num;
	unsigned char* ms_confirm_msg;
	unsigned char* ms_confirm_sig;
} ms_ecall_create_confirm_msg_t;

typedef struct ms_ecall_verify_ag_res_msg_t {
	unsigned char* ms_pubaddr;
	unsigned char* ms_res_msg;
	unsigned char* ms_res_sig;
	unsigned int* ms_is_verified;
} ms_ecall_verify_ag_res_msg_t;

typedef struct ms_ecall_verify_ud_res_msg_t {
	unsigned char* ms_pubaddr;
	unsigned char* ms_res_msg;
	unsigned char* ms_res_sig;
	unsigned int* ms_is_verified;
} ms_ecall_verify_ud_res_msg_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	1,
	{
		(void*)enclave_ocall_print_string,
	}
};
sgx_status_t ecall_accept_request(sgx_enclave_id_t eid, unsigned char* sender, unsigned char* receiver, unsigned int amount, unsigned int* payment_num)
{
	sgx_status_t status;
	ms_ecall_accept_request_t ms;
	ms.ms_sender = sender;
	ms.ms_receiver = receiver;
	ms.ms_amount = amount;
	ms.ms_payment_num = payment_num;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_add_participant(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* addr)
{
	sgx_status_t status;
	ms_ecall_add_participant_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_addr = addr;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_update_sentagr_list(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* addr)
{
	sgx_status_t status;
	ms_ecall_update_sentagr_list_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_addr = addr;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_update_sentupt_list(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* addr)
{
	sgx_status_t status;
	ms_ecall_update_sentupt_list_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_addr = addr;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_check_unanimity(sgx_enclave_id_t eid, unsigned int payment_num, int which_list, int* is_unanimous)
{
	sgx_status_t status;
	ms_ecall_check_unanimity_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_which_list = which_list;
	ms.ms_is_unanimous = is_unanimous;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_update_payment_status_to_success(sgx_enclave_id_t eid, unsigned int payment_num)
{
	sgx_status_t status;
	ms_ecall_update_payment_status_to_success_t ms;
	ms.ms_payment_num = payment_num;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_create_ag_req_msg(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int payment_size, unsigned int* channel_ids, int* amount, unsigned char* req_msg, unsigned char* req_sig)
{
	sgx_status_t status;
	ms_ecall_create_ag_req_msg_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_payment_size = payment_size;
	ms.ms_channel_ids = channel_ids;
	ms.ms_amount = amount;
	ms.ms_req_msg = req_msg;
	ms.ms_req_sig = req_sig;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_create_ud_req_msg(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int payment_size, unsigned int* channel_ids, int* amount, unsigned char* req_msg, unsigned char* req_sig)
{
	sgx_status_t status;
	ms_ecall_create_ud_req_msg_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_payment_size = payment_size;
	ms.ms_channel_ids = channel_ids;
	ms.ms_amount = amount;
	ms.ms_req_msg = req_msg;
	ms.ms_req_sig = req_sig;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_create_confirm_msg(sgx_enclave_id_t eid, unsigned int payment_num, unsigned char* confirm_msg, unsigned char* confirm_sig)
{
	sgx_status_t status;
	ms_ecall_create_confirm_msg_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_confirm_msg = confirm_msg;
	ms.ms_confirm_sig = confirm_sig;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_verify_ag_res_msg(sgx_enclave_id_t eid, unsigned char* pubaddr, unsigned char* res_msg, unsigned char* res_sig, unsigned int* is_verified)
{
	sgx_status_t status;
	ms_ecall_verify_ag_res_msg_t ms;
	ms.ms_pubaddr = pubaddr;
	ms.ms_res_msg = res_msg;
	ms.ms_res_sig = res_sig;
	ms.ms_is_verified = is_verified;
	status = sgx_ecall(eid, 9, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_verify_ud_res_msg(sgx_enclave_id_t eid, unsigned char* pubaddr, unsigned char* res_msg, unsigned char* res_sig, unsigned int* is_verified)
{
	sgx_status_t status;
	ms_ecall_verify_ud_res_msg_t ms;
	ms.ms_pubaddr = pubaddr;
	ms.ms_res_msg = res_msg;
	ms.ms_res_sig = res_sig;
	ms.ms_is_verified = is_verified;
	status = sgx_ecall(eid, 10, &ocall_table_enclave, &ms);
	return status;
}

