#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_preset_account(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_preset_account_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_preset_account_t* ms = SGX_CAST(ms_ecall_preset_account_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_addr = ms->ms_addr;
	size_t _len_addr = 40;
	unsigned char* _in_addr = NULL;
	unsigned char* _tmp_seckey = ms->ms_seckey;
	size_t _len_seckey = 64;
	unsigned char* _in_seckey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_addr, _len_addr);
	CHECK_UNIQUE_POINTER(_tmp_seckey, _len_seckey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_addr != NULL && _len_addr != 0) {
		if ( _len_addr % sizeof(*_tmp_addr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_addr = (unsigned char*)malloc(_len_addr);
		if (_in_addr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_addr, _len_addr, _tmp_addr, _len_addr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_seckey != NULL && _len_seckey != 0) {
		if ( _len_seckey % sizeof(*_tmp_seckey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_seckey = (unsigned char*)malloc(_len_seckey);
		if (_in_seckey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_seckey, _len_seckey, _tmp_seckey, _len_seckey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_preset_account(_in_addr, _in_seckey);

err:
	if (_in_addr) free(_in_addr);
	if (_in_seckey) free(_in_seckey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_preset_payment(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_preset_payment_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_preset_payment_t* ms = SGX_CAST(ms_ecall_preset_payment_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_preset_payment(ms->ms_pn, ms->ms_channel_id, ms->ms_amount);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_account(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_account_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_account_t* ms = SGX_CAST(ms_ecall_create_account_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_generated_addr = ms->ms_generated_addr;



	ecall_create_account(_tmp_generated_addr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_channel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_channel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_channel_t* ms = SGX_CAST(ms_ecall_create_channel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_owner = ms->ms_owner;
	size_t _len_owner = 40;
	unsigned char* _in_owner = NULL;
	unsigned char* _tmp_receiver = ms->ms_receiver;
	size_t _len_receiver = 40;
	unsigned char* _in_receiver = NULL;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;

	CHECK_UNIQUE_POINTER(_tmp_owner, _len_owner);
	CHECK_UNIQUE_POINTER(_tmp_receiver, _len_receiver);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_owner != NULL && _len_owner != 0) {
		if ( _len_owner % sizeof(*_tmp_owner) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_owner = (unsigned char*)malloc(_len_owner);
		if (_in_owner == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_owner, _len_owner, _tmp_owner, _len_owner)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_receiver != NULL && _len_receiver != 0) {
		if ( _len_receiver % sizeof(*_tmp_receiver) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_receiver = (unsigned char*)malloc(_len_receiver);
		if (_in_receiver == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_receiver, _len_receiver, _tmp_receiver, _len_receiver)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_create_channel(ms->ms_nonce, _in_owner, _in_receiver, ms->ms_deposit, _tmp_signed_tx, _tmp_signed_tx_len);

err:
	if (_in_owner) free(_in_owner);
	if (_in_receiver) free(_in_receiver);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_onchain_payment(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_onchain_payment_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_onchain_payment_t* ms = SGX_CAST(ms_ecall_onchain_payment_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_owner = ms->ms_owner;
	size_t _len_owner = 40;
	unsigned char* _in_owner = NULL;
	unsigned char* _tmp_receiver = ms->ms_receiver;
	size_t _len_receiver = 40;
	unsigned char* _in_receiver = NULL;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;

	CHECK_UNIQUE_POINTER(_tmp_owner, _len_owner);
	CHECK_UNIQUE_POINTER(_tmp_receiver, _len_receiver);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_owner != NULL && _len_owner != 0) {
		if ( _len_owner % sizeof(*_tmp_owner) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_owner = (unsigned char*)malloc(_len_owner);
		if (_in_owner == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_owner, _len_owner, _tmp_owner, _len_owner)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_receiver != NULL && _len_receiver != 0) {
		if ( _len_receiver % sizeof(*_tmp_receiver) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_receiver = (unsigned char*)malloc(_len_receiver);
		if (_in_receiver == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_receiver, _len_receiver, _tmp_receiver, _len_receiver)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_onchain_payment(ms->ms_nonce, _in_owner, _in_receiver, ms->ms_amount, _tmp_signed_tx, _tmp_signed_tx_len);

err:
	if (_in_owner) free(_in_owner);
	if (_in_receiver) free(_in_receiver);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pay(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pay_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pay_t* ms = SGX_CAST(ms_ecall_pay_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_is_success = ms->ms_is_success;
	unsigned char* _tmp_original_msg = ms->ms_original_msg;
	unsigned char* _tmp_output = ms->ms_output;



	ecall_pay(ms->ms_channel_id, ms->ms_amount, _tmp_is_success, _tmp_original_msg, _tmp_output);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_paid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_paid_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_paid_t* ms = SGX_CAST(ms_ecall_paid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_msg = ms->ms_msg;
	unsigned char* _tmp_signature = ms->ms_signature;
	unsigned char* _tmp_original_msg = ms->ms_original_msg;
	unsigned char* _tmp_output = ms->ms_output;



	ecall_paid(_tmp_msg, _tmp_signature, _tmp_original_msg, _tmp_output);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pay_accepted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pay_accepted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pay_accepted_t* ms = SGX_CAST(ms_ecall_pay_accepted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_msg = ms->ms_msg;
	unsigned char* _tmp_signature = ms->ms_signature;



	ecall_pay_accepted(_tmp_msg, _tmp_signature);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_balance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_balance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_balance_t* ms = SGX_CAST(ms_ecall_get_balance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_balance = ms->ms_balance;



	ecall_get_balance(ms->ms_channel_id, _tmp_balance);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_channel_info(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_channel_info_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_channel_info_t* ms = SGX_CAST(ms_ecall_get_channel_info_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_channel_info = ms->ms_channel_info;



	ecall_get_channel_info(ms->ms_channel_id, _tmp_channel_info);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_close_channel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_close_channel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_close_channel_t* ms = SGX_CAST(ms_ecall_close_channel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;



	ecall_close_channel(ms->ms_nonce, ms->ms_channel_id, _tmp_signed_tx, _tmp_signed_tx_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_eject(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_eject_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_eject_t* ms = SGX_CAST(ms_ecall_eject_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;



	ecall_eject(ms->ms_nonce, ms->ms_pn, _tmp_signed_tx, _tmp_signed_tx_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_num_open_channels(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_num_open_channels_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_num_open_channels_t* ms = SGX_CAST(ms_ecall_get_num_open_channels_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_num_open_channels = ms->ms_num_open_channels;



	ecall_get_num_open_channels(_tmp_num_open_channels);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_open_channels(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_open_channels_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_open_channels_t* ms = SGX_CAST(ms_ecall_get_open_channels_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_open_channels = ms->ms_open_channels;



	ecall_get_open_channels(_tmp_open_channels);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_num_closed_channels(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_num_closed_channels_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_num_closed_channels_t* ms = SGX_CAST(ms_ecall_get_num_closed_channels_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_num_closed_channels = ms->ms_num_closed_channels;



	ecall_get_num_closed_channels(_tmp_num_closed_channels);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_closed_channels(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_closed_channels_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_closed_channels_t* ms = SGX_CAST(ms_ecall_get_closed_channels_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_closed_channels = ms->ms_closed_channels;



	ecall_get_closed_channels(_tmp_closed_channels);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_num_public_addrs(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_num_public_addrs_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_num_public_addrs_t* ms = SGX_CAST(ms_ecall_get_num_public_addrs_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_num_public_addrs = ms->ms_num_public_addrs;



	ecall_get_num_public_addrs(_tmp_num_public_addrs);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_public_addrs(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_public_addrs_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_public_addrs_t* ms = SGX_CAST(ms_ecall_get_public_addrs_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_public_addrs = ms->ms_public_addrs;



	ecall_get_public_addrs(_tmp_public_addrs);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_test_func(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_test_func();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_receive_create_channel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_receive_create_channel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_receive_create_channel_t* ms = SGX_CAST(ms_ecall_receive_create_channel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_owner = ms->ms_owner;
	size_t _len_owner = 40;
	unsigned char* _in_owner = NULL;
	unsigned char* _tmp_receiver = ms->ms_receiver;
	size_t _len_receiver = 40;
	unsigned char* _in_receiver = NULL;

	CHECK_UNIQUE_POINTER(_tmp_owner, _len_owner);
	CHECK_UNIQUE_POINTER(_tmp_receiver, _len_receiver);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_owner != NULL && _len_owner != 0) {
		if ( _len_owner % sizeof(*_tmp_owner) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_owner = (unsigned char*)malloc(_len_owner);
		if (_in_owner == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_owner, _len_owner, _tmp_owner, _len_owner)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_receiver != NULL && _len_receiver != 0) {
		if ( _len_receiver % sizeof(*_tmp_receiver) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_receiver = (unsigned char*)malloc(_len_receiver);
		if (_in_receiver == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_receiver, _len_receiver, _tmp_receiver, _len_receiver)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_receive_create_channel(ms->ms_channel_id, _in_owner, _in_receiver, ms->ms_deposit);

err:
	if (_in_owner) free(_in_owner);
	if (_in_receiver) free(_in_receiver);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_receive_close_channel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_receive_close_channel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_receive_close_channel_t* ms = SGX_CAST(ms_ecall_receive_close_channel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_receive_close_channel(ms->ms_channel_id, ms->ms_owner_bal, ms->ms_receiver_bal);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_go_pre_update(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_go_pre_update_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_go_pre_update_t* ms = SGX_CAST(ms_ecall_go_pre_update_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_msg = ms->ms_msg;
	unsigned char* _tmp_signature = ms->ms_signature;
	unsigned char* _tmp_original_msg = ms->ms_original_msg;
	unsigned char* _tmp_output = ms->ms_output;



	ecall_go_pre_update(_tmp_msg, _tmp_signature, _tmp_original_msg, _tmp_output);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_go_post_update(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_go_post_update_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_go_post_update_t* ms = SGX_CAST(ms_ecall_go_post_update_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_msg = ms->ms_msg;
	unsigned char* _tmp_signature = ms->ms_signature;
	unsigned char* _tmp_original_msg = ms->ms_original_msg;
	unsigned char* _tmp_output = ms->ms_output;



	ecall_go_post_update(_tmp_msg, _tmp_signature, _tmp_original_msg, _tmp_output);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_go_idle(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_go_idle_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_go_idle_t* ms = SGX_CAST(ms_ecall_go_idle_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_msg = ms->ms_msg;
	unsigned char* _tmp_signature = ms->ms_signature;



	ecall_go_idle(_tmp_msg, _tmp_signature);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_register_comminfo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_register_comminfo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_register_comminfo_t* ms = SGX_CAST(ms_ecall_register_comminfo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_ip = ms->ms_ip;



	ecall_register_comminfo(ms->ms_channel_id, _tmp_ip, ms->ms_ip_size, ms->ms_port);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_store_account_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_store_account_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_store_account_data_t* ms = SGX_CAST(ms_ecall_store_account_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_keyfile = ms->ms_keyfile;



	ecall_store_account_data(_tmp_keyfile);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_store_channel_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_store_channel_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_store_channel_data_t* ms = SGX_CAST(ms_ecall_store_channel_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_chfile = ms->ms_chfile;



	ecall_store_channel_data(_tmp_chfile);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_account_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_account_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_account_data_t* ms = SGX_CAST(ms_ecall_load_account_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sealed_seckey = ms->ms_sealed_seckey;
	size_t _len_sealed_seckey = 592;
	unsigned char* _in_sealed_seckey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_seckey, _len_sealed_seckey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_seckey != NULL && _len_sealed_seckey != 0) {
		if ( _len_sealed_seckey % sizeof(*_tmp_sealed_seckey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_seckey = (unsigned char*)malloc(_len_sealed_seckey);
		if (_in_sealed_seckey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_seckey, _len_sealed_seckey, _tmp_sealed_seckey, _len_sealed_seckey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_load_account_data(_in_sealed_seckey);

err:
	if (_in_sealed_seckey) free(_in_sealed_seckey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_channel_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_channel_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_channel_data_t* ms = SGX_CAST(ms_ecall_load_channel_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sealed_channel_data = ms->ms_sealed_channel_data;
	size_t _len_sealed_channel_data = 628;
	unsigned char* _in_sealed_channel_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_channel_data, _len_sealed_channel_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_channel_data != NULL && _len_sealed_channel_data != 0) {
		if ( _len_sealed_channel_data % sizeof(*_tmp_sealed_channel_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_channel_data = (unsigned char*)malloc(_len_sealed_channel_data);
		if (_in_sealed_channel_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_channel_data, _len_sealed_channel_data, _tmp_sealed_channel_data, _len_sealed_channel_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_load_channel_data(_in_sealed_channel_data);

err:
	if (_in_sealed_channel_data) free(_in_sealed_channel_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[29];
} g_ecall_table = {
	29,
	{
		{(void*)(uintptr_t)sgx_ecall_preset_account, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_preset_payment, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_account, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_channel, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_onchain_payment, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pay, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_paid, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pay_accepted, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_balance, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_channel_info, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_close_channel, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_eject, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_num_open_channels, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_open_channels, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_num_closed_channels, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_closed_channels, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_num_public_addrs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_public_addrs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_test_func, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_receive_create_channel, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_receive_close_channel, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_go_pre_update, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_go_post_update, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_go_idle, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_register_comminfo, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_store_account_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_store_channel_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_load_account_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_load_channel_data, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][29];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_remove_key_file(char* keyfile)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_remove_key_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_remove_key_file_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_remove_key_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_remove_key_file_t));
	ocalloc_size -= sizeof(ms_ocall_remove_key_file_t);

	ms->ms_keyfile = keyfile;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_store_sealed_seckey(char* keyfile, unsigned char* sealed_seckey)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_seckey = 592;

	ms_ocall_store_sealed_seckey_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_store_sealed_seckey_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealed_seckey, _len_sealed_seckey);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_seckey != NULL) ? _len_sealed_seckey : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_store_sealed_seckey_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_store_sealed_seckey_t));
	ocalloc_size -= sizeof(ms_ocall_store_sealed_seckey_t);

	ms->ms_keyfile = keyfile;
	if (sealed_seckey != NULL) {
		ms->ms_sealed_seckey = (unsigned char*)__tmp;
		if (_len_sealed_seckey % sizeof(*sealed_seckey) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealed_seckey, _len_sealed_seckey)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed_seckey);
		ocalloc_size -= _len_sealed_seckey;
	} else {
		ms->ms_sealed_seckey = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_remove_channel_file(char* chfile)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_remove_channel_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_remove_channel_file_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_remove_channel_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_remove_channel_file_t));
	ocalloc_size -= sizeof(ms_ocall_remove_channel_file_t);

	ms->ms_chfile = chfile;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_store_sealed_channel_data(char* chfile, unsigned char* sealed_seckey)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_seckey = 628;

	ms_ocall_store_sealed_channel_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_store_sealed_channel_data_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealed_seckey, _len_sealed_seckey);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_seckey != NULL) ? _len_sealed_seckey : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_store_sealed_channel_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_store_sealed_channel_data_t));
	ocalloc_size -= sizeof(ms_ocall_store_sealed_channel_data_t);

	ms->ms_chfile = chfile;
	if (sealed_seckey != NULL) {
		ms->ms_sealed_seckey = (unsigned char*)__tmp;
		if (_len_sealed_seckey % sizeof(*sealed_seckey) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealed_seckey, _len_sealed_seckey)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed_seckey);
		ocalloc_size -= _len_sealed_seckey;
	} else {
		ms->ms_sealed_seckey = NULL;
	}
	
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

