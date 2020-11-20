#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_preset_account_t {
	unsigned char* ms_addr;
	unsigned char* ms_seckey;
} ms_ecall_preset_account_t;

typedef struct ms_ecall_preset_payment_t {
	unsigned int ms_pn;
	unsigned int ms_channel_id;
	int ms_amount;
} ms_ecall_preset_payment_t;

typedef struct ms_ecall_create_account_t {
	unsigned char* ms_generated_addr;
} ms_ecall_create_account_t;

typedef struct ms_ecall_create_channel_t {
	unsigned int ms_nonce;
	unsigned char* ms_owner;
	unsigned char* ms_receiver;
	unsigned int ms_deposit;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_create_channel_t;

typedef struct ms_ecall_onchain_payment_t {
	unsigned int ms_nonce;
	unsigned char* ms_owner;
	unsigned char* ms_receiver;
	unsigned int ms_amount;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_onchain_payment_t;

typedef struct ms_ecall_pay_t {
	unsigned int ms_channel_id;
	unsigned int ms_amount;
	int* ms_is_success;
	unsigned char* ms_original_msg;
	unsigned char* ms_output;
} ms_ecall_pay_t;

typedef struct ms_ecall_paid_t {
	unsigned char* ms_msg;
	unsigned char* ms_signature;
	unsigned char* ms_original_msg;
	unsigned char* ms_output;
} ms_ecall_paid_t;

typedef struct ms_ecall_pay_accepted_t {
	unsigned char* ms_msg;
	unsigned char* ms_signature;
} ms_ecall_pay_accepted_t;

typedef struct ms_ecall_get_balance_t {
	unsigned int ms_channel_id;
	unsigned int* ms_balance;
} ms_ecall_get_balance_t;

typedef struct ms_ecall_get_channel_info_t {
	unsigned int ms_channel_id;
	unsigned char* ms_channel_info;
} ms_ecall_get_channel_info_t;

typedef struct ms_ecall_close_channel_t {
	unsigned int ms_nonce;
	unsigned int ms_channel_id;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_close_channel_t;

typedef struct ms_ecall_eject_t {
	unsigned int ms_nonce;
	unsigned int ms_pn;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_eject_t;

typedef struct ms_ecall_get_num_open_channels_t {
	unsigned int* ms_num_open_channels;
} ms_ecall_get_num_open_channels_t;

typedef struct ms_ecall_get_open_channels_t {
	unsigned char* ms_open_channels;
} ms_ecall_get_open_channels_t;

typedef struct ms_ecall_get_num_closed_channels_t {
	unsigned int* ms_num_closed_channels;
} ms_ecall_get_num_closed_channels_t;

typedef struct ms_ecall_get_closed_channels_t {
	unsigned char* ms_closed_channels;
} ms_ecall_get_closed_channels_t;

typedef struct ms_ecall_get_num_public_addrs_t {
	unsigned int* ms_num_public_addrs;
} ms_ecall_get_num_public_addrs_t;

typedef struct ms_ecall_get_public_addrs_t {
	unsigned char* ms_public_addrs;
} ms_ecall_get_public_addrs_t;

typedef struct ms_ecall_receive_create_channel_t {
	unsigned int ms_channel_id;
	unsigned char* ms_owner;
	unsigned char* ms_receiver;
	unsigned int ms_deposit;
} ms_ecall_receive_create_channel_t;

typedef struct ms_ecall_receive_close_channel_t {
	unsigned int ms_channel_id;
	unsigned int ms_owner_bal;
	unsigned int ms_receiver_bal;
} ms_ecall_receive_close_channel_t;

typedef struct ms_ecall_go_pre_update_t {
	unsigned char* ms_msg;
	unsigned char* ms_signature;
	unsigned char* ms_original_msg;
	unsigned char* ms_output;
} ms_ecall_go_pre_update_t;

typedef struct ms_ecall_go_post_update_t {
	unsigned char* ms_msg;
	unsigned char* ms_signature;
	unsigned char* ms_original_msg;
	unsigned char* ms_output;
} ms_ecall_go_post_update_t;

typedef struct ms_ecall_go_idle_t {
	unsigned char* ms_msg;
	unsigned char* ms_signature;
} ms_ecall_go_idle_t;

typedef struct ms_ecall_register_comminfo_t {
	unsigned int ms_channel_id;
	unsigned char* ms_ip;
	unsigned int ms_ip_size;
	unsigned int ms_port;
} ms_ecall_register_comminfo_t;

typedef struct ms_ecall_store_account_data_t {
	char* ms_keyfile;
} ms_ecall_store_account_data_t;

typedef struct ms_ecall_store_channel_data_t {
	char* ms_chfile;
} ms_ecall_store_channel_data_t;

typedef struct ms_ecall_load_account_data_t {
	unsigned char* ms_sealed_seckey;
} ms_ecall_load_account_data_t;

typedef struct ms_ecall_load_channel_data_t {
	unsigned char* ms_sealed_channel_data;
} ms_ecall_load_channel_data_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_remove_key_file_t {
	char* ms_keyfile;
} ms_ocall_remove_key_file_t;

typedef struct ms_ocall_store_sealed_seckey_t {
	char* ms_keyfile;
	unsigned char* ms_sealed_seckey;
} ms_ocall_store_sealed_seckey_t;

typedef struct ms_ocall_remove_channel_file_t {
	char* ms_chfile;
} ms_ocall_remove_channel_file_t;

typedef struct ms_ocall_store_sealed_channel_data_t {
	char* ms_chfile;
	unsigned char* ms_sealed_seckey;
} ms_ocall_store_sealed_channel_data_t;

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_remove_key_file(void* pms)
{
	ms_ocall_remove_key_file_t* ms = SGX_CAST(ms_ocall_remove_key_file_t*, pms);
	ocall_remove_key_file(ms->ms_keyfile);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_store_sealed_seckey(void* pms)
{
	ms_ocall_store_sealed_seckey_t* ms = SGX_CAST(ms_ocall_store_sealed_seckey_t*, pms);
	ocall_store_sealed_seckey(ms->ms_keyfile, ms->ms_sealed_seckey);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_remove_channel_file(void* pms)
{
	ms_ocall_remove_channel_file_t* ms = SGX_CAST(ms_ocall_remove_channel_file_t*, pms);
	ocall_remove_channel_file(ms->ms_chfile);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_store_sealed_channel_data(void* pms)
{
	ms_ocall_store_sealed_channel_data_t* ms = SGX_CAST(ms_ocall_store_sealed_channel_data_t*, pms);
	ocall_store_sealed_channel_data(ms->ms_chfile, ms->ms_sealed_seckey);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_enclave = {
	5,
	{
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_remove_key_file,
		(void*)enclave_ocall_store_sealed_seckey,
		(void*)enclave_ocall_remove_channel_file,
		(void*)enclave_ocall_store_sealed_channel_data,
	}
};
sgx_status_t ecall_preset_account(sgx_enclave_id_t eid, unsigned char* addr, unsigned char* seckey)
{
	sgx_status_t status;
	ms_ecall_preset_account_t ms;
	ms.ms_addr = addr;
	ms.ms_seckey = seckey;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_preset_payment(sgx_enclave_id_t eid, unsigned int pn, unsigned int channel_id, int amount)
{
	sgx_status_t status;
	ms_ecall_preset_payment_t ms;
	ms.ms_pn = pn;
	ms.ms_channel_id = channel_id;
	ms.ms_amount = amount;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_create_account(sgx_enclave_id_t eid, unsigned char* generated_addr)
{
	sgx_status_t status;
	ms_ecall_create_account_t ms;
	ms.ms_generated_addr = generated_addr;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_create_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int deposit, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_create_channel_t ms;
	ms.ms_nonce = nonce;
	ms.ms_owner = owner;
	ms.ms_receiver = receiver;
	ms.ms_deposit = deposit;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_onchain_payment(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int amount, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_onchain_payment_t ms;
	ms.ms_nonce = nonce;
	ms.ms_owner = owner;
	ms.ms_receiver = receiver;
	ms.ms_amount = amount;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_pay(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int amount, int* is_success, unsigned char* original_msg, unsigned char* output)
{
	sgx_status_t status;
	ms_ecall_pay_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_amount = amount;
	ms.ms_is_success = is_success;
	ms.ms_original_msg = original_msg;
	ms.ms_output = output;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_paid(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output)
{
	sgx_status_t status;
	ms_ecall_paid_t ms;
	ms.ms_msg = msg;
	ms.ms_signature = signature;
	ms.ms_original_msg = original_msg;
	ms.ms_output = output;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_pay_accepted(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature)
{
	sgx_status_t status;
	ms_ecall_pay_accepted_t ms;
	ms.ms_msg = msg;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_balance(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int* balance)
{
	sgx_status_t status;
	ms_ecall_get_balance_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_balance = balance;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_channel_info(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* channel_info)
{
	sgx_status_t status;
	ms_ecall_get_channel_info_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_channel_info = channel_info;
	status = sgx_ecall(eid, 9, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_close_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned int channel_id, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_close_channel_t ms;
	ms.ms_nonce = nonce;
	ms.ms_channel_id = channel_id;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 10, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_eject(sgx_enclave_id_t eid, unsigned int nonce, unsigned int pn, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_eject_t ms;
	ms.ms_nonce = nonce;
	ms.ms_pn = pn;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 11, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_num_open_channels(sgx_enclave_id_t eid, unsigned int* num_open_channels)
{
	sgx_status_t status;
	ms_ecall_get_num_open_channels_t ms;
	ms.ms_num_open_channels = num_open_channels;
	status = sgx_ecall(eid, 12, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_open_channels(sgx_enclave_id_t eid, unsigned char* open_channels)
{
	sgx_status_t status;
	ms_ecall_get_open_channels_t ms;
	ms.ms_open_channels = open_channels;
	status = sgx_ecall(eid, 13, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_num_closed_channels(sgx_enclave_id_t eid, unsigned int* num_closed_channels)
{
	sgx_status_t status;
	ms_ecall_get_num_closed_channels_t ms;
	ms.ms_num_closed_channels = num_closed_channels;
	status = sgx_ecall(eid, 14, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_closed_channels(sgx_enclave_id_t eid, unsigned char* closed_channels)
{
	sgx_status_t status;
	ms_ecall_get_closed_channels_t ms;
	ms.ms_closed_channels = closed_channels;
	status = sgx_ecall(eid, 15, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_num_public_addrs(sgx_enclave_id_t eid, unsigned int* num_public_addrs)
{
	sgx_status_t status;
	ms_ecall_get_num_public_addrs_t ms;
	ms.ms_num_public_addrs = num_public_addrs;
	status = sgx_ecall(eid, 16, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_public_addrs(sgx_enclave_id_t eid, unsigned char* public_addrs)
{
	sgx_status_t status;
	ms_ecall_get_public_addrs_t ms;
	ms.ms_public_addrs = public_addrs;
	status = sgx_ecall(eid, 17, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_test_func(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 18, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t ecall_receive_create_channel(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* owner, unsigned char* receiver, unsigned int deposit)
{
	sgx_status_t status;
	ms_ecall_receive_create_channel_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_owner = owner;
	ms.ms_receiver = receiver;
	ms.ms_deposit = deposit;
	status = sgx_ecall(eid, 19, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_receive_close_channel(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int owner_bal, unsigned int receiver_bal)
{
	sgx_status_t status;
	ms_ecall_receive_close_channel_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_owner_bal = owner_bal;
	ms.ms_receiver_bal = receiver_bal;
	status = sgx_ecall(eid, 20, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_go_pre_update(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output)
{
	sgx_status_t status;
	ms_ecall_go_pre_update_t ms;
	ms.ms_msg = msg;
	ms.ms_signature = signature;
	ms.ms_original_msg = original_msg;
	ms.ms_output = output;
	status = sgx_ecall(eid, 21, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_go_post_update(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature, unsigned char* original_msg, unsigned char* output)
{
	sgx_status_t status;
	ms_ecall_go_post_update_t ms;
	ms.ms_msg = msg;
	ms.ms_signature = signature;
	ms.ms_original_msg = original_msg;
	ms.ms_output = output;
	status = sgx_ecall(eid, 22, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_go_idle(sgx_enclave_id_t eid, unsigned char* msg, unsigned char* signature)
{
	sgx_status_t status;
	ms_ecall_go_idle_t ms;
	ms.ms_msg = msg;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 23, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_register_comminfo(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* ip, unsigned int ip_size, unsigned int port)
{
	sgx_status_t status;
	ms_ecall_register_comminfo_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_ip = ip;
	ms.ms_ip_size = ip_size;
	ms.ms_port = port;
	status = sgx_ecall(eid, 24, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_store_account_data(sgx_enclave_id_t eid, char* keyfile)
{
	sgx_status_t status;
	ms_ecall_store_account_data_t ms;
	ms.ms_keyfile = keyfile;
	status = sgx_ecall(eid, 25, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_store_channel_data(sgx_enclave_id_t eid, char* chfile)
{
	sgx_status_t status;
	ms_ecall_store_channel_data_t ms;
	ms.ms_chfile = chfile;
	status = sgx_ecall(eid, 26, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_load_account_data(sgx_enclave_id_t eid, unsigned char* sealed_seckey)
{
	sgx_status_t status;
	ms_ecall_load_account_data_t ms;
	ms.ms_sealed_seckey = sealed_seckey;
	status = sgx_ecall(eid, 27, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_load_channel_data(sgx_enclave_id_t eid, unsigned char* sealed_channel_data)
{
	sgx_status_t status;
	ms_ecall_load_channel_data_t ms;
	ms.ms_sealed_channel_data = sealed_channel_data;
	status = sgx_ecall(eid, 28, &ocall_table_enclave, &ms);
	return status;
}

