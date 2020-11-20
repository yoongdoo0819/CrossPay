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

static sgx_status_t SGX_CDECL sgx_ecall_accept_request(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_accept_request_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_accept_request_t* ms = SGX_CAST(ms_ecall_accept_request_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sender = ms->ms_sender;
	size_t _len_sender = 40;
	unsigned char* _in_sender = NULL;
	unsigned char* _tmp_receiver = ms->ms_receiver;
	size_t _len_receiver = 40;
	unsigned char* _in_receiver = NULL;
	unsigned int* _tmp_payment_num = ms->ms_payment_num;

	CHECK_UNIQUE_POINTER(_tmp_sender, _len_sender);
	CHECK_UNIQUE_POINTER(_tmp_receiver, _len_receiver);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sender != NULL && _len_sender != 0) {
		if ( _len_sender % sizeof(*_tmp_sender) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sender = (unsigned char*)malloc(_len_sender);
		if (_in_sender == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sender, _len_sender, _tmp_sender, _len_sender)) {
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

	ecall_accept_request(_in_sender, _in_receiver, ms->ms_amount, _tmp_payment_num);

err:
	if (_in_sender) free(_in_sender);
	if (_in_receiver) free(_in_receiver);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add_participant(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_participant_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_participant_t* ms = SGX_CAST(ms_ecall_add_participant_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_addr = ms->ms_addr;
	size_t _len_addr = 40;
	unsigned char* _in_addr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_addr, _len_addr);

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

	ecall_add_participant(ms->ms_payment_num, _in_addr);

err:
	if (_in_addr) free(_in_addr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_update_sentagr_list(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_update_sentagr_list_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_update_sentagr_list_t* ms = SGX_CAST(ms_ecall_update_sentagr_list_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_addr = ms->ms_addr;
	size_t _len_addr = 40;
	unsigned char* _in_addr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_addr, _len_addr);

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

	ecall_update_sentagr_list(ms->ms_payment_num, _in_addr);

err:
	if (_in_addr) free(_in_addr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_update_sentupt_list(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_update_sentupt_list_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_update_sentupt_list_t* ms = SGX_CAST(ms_ecall_update_sentupt_list_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_addr = ms->ms_addr;
	size_t _len_addr = 40;
	unsigned char* _in_addr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_addr, _len_addr);

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

	ecall_update_sentupt_list(ms->ms_payment_num, _in_addr);

err:
	if (_in_addr) free(_in_addr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_check_unanimity(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_check_unanimity_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_check_unanimity_t* ms = SGX_CAST(ms_ecall_check_unanimity_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_is_unanimous = ms->ms_is_unanimous;



	ecall_check_unanimity(ms->ms_payment_num, ms->ms_which_list, _tmp_is_unanimous);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_update_payment_status_to_success(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_update_payment_status_to_success_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_update_payment_status_to_success_t* ms = SGX_CAST(ms_ecall_update_payment_status_to_success_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_update_payment_status_to_success(ms->ms_payment_num);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_ag_req_msg(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_ag_req_msg_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_ag_req_msg_t* ms = SGX_CAST(ms_ecall_create_ag_req_msg_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_channel_ids = ms->ms_channel_ids;
	int* _tmp_amount = ms->ms_amount;
	unsigned char* _tmp_req_msg = ms->ms_req_msg;
	unsigned char* _tmp_req_sig = ms->ms_req_sig;



	ecall_create_ag_req_msg(ms->ms_payment_num, ms->ms_payment_size, _tmp_channel_ids, _tmp_amount, _tmp_req_msg, _tmp_req_sig);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_ud_req_msg(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_ud_req_msg_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_ud_req_msg_t* ms = SGX_CAST(ms_ecall_create_ud_req_msg_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_channel_ids = ms->ms_channel_ids;
	int* _tmp_amount = ms->ms_amount;
	unsigned char* _tmp_req_msg = ms->ms_req_msg;
	unsigned char* _tmp_req_sig = ms->ms_req_sig;



	ecall_create_ud_req_msg(ms->ms_payment_num, ms->ms_payment_size, _tmp_channel_ids, _tmp_amount, _tmp_req_msg, _tmp_req_sig);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_confirm_msg(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_confirm_msg_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_confirm_msg_t* ms = SGX_CAST(ms_ecall_create_confirm_msg_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_confirm_msg = ms->ms_confirm_msg;
	unsigned char* _tmp_confirm_sig = ms->ms_confirm_sig;



	ecall_create_confirm_msg(ms->ms_payment_num, _tmp_confirm_msg, _tmp_confirm_sig);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify_ag_res_msg(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_ag_res_msg_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_ag_res_msg_t* ms = SGX_CAST(ms_ecall_verify_ag_res_msg_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_pubaddr = ms->ms_pubaddr;
	unsigned char* _tmp_res_msg = ms->ms_res_msg;
	unsigned char* _tmp_res_sig = ms->ms_res_sig;
	unsigned int* _tmp_is_verified = ms->ms_is_verified;



	ecall_verify_ag_res_msg(_tmp_pubaddr, _tmp_res_msg, _tmp_res_sig, _tmp_is_verified);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify_ud_res_msg(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_ud_res_msg_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_ud_res_msg_t* ms = SGX_CAST(ms_ecall_verify_ud_res_msg_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_pubaddr = ms->ms_pubaddr;
	unsigned char* _tmp_res_msg = ms->ms_res_msg;
	unsigned char* _tmp_res_sig = ms->ms_res_sig;
	unsigned int* _tmp_is_verified = ms->ms_is_verified;



	ecall_verify_ud_res_msg(_tmp_pubaddr, _tmp_res_msg, _tmp_res_sig, _tmp_is_verified);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_ecall_accept_request, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add_participant, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_update_sentagr_list, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_update_sentupt_list, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_check_unanimity, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_update_payment_status_to_success, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_ag_req_msg, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_ud_req_msg, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_confirm_msg, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_verify_ag_res_msg, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_verify_ud_res_msg, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][11];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
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

