#include "app.h"
#include "enclave_u.h"

#include <mutex>
//using namespace std;
std::mutex rwMutex;

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
	{									                        SGX_ERROR_ENCLAVE_LOST,
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
/*
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
*/
/*  OCall functions */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

unsigned int ecall_accept_request_w(unsigned char *sender, unsigned char *receiver, unsigned int amount)
{
    unsigned int payment_num;

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
	ret = ecall_accept_request(global_eid, sender, receiver, amount, &payment_num);		 
	if (ret != SGX_SUCCESS) {
		// print_error_message(ret);
		return 999999;
	}

    return payment_num;
}


void ecall_add_participant_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_add_participant(global_eid, payment_num, addr);
}


void ecall_update_sentagr_list_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_update_sentagr_list(global_eid, payment_num, addr);
}


void ecall_update_sentupt_list_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_update_sentupt_list(global_eid, payment_num, addr);
}


int ecall_check_unanimity_w(unsigned int payment_num, int which_list)
{
    int is_unanimous;

    ecall_check_unanimity(global_eid, payment_num, which_list, &is_unanimous);

    return is_unanimous;
}

void ecall_update_payment_status_to_success_w(unsigned int payment_num)
{
    ecall_update_payment_status_to_success(global_eid, payment_num);
}


void ecall_create_ag_req_msg_w(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *req_msg = new unsigned char[sizeof(message)];
    unsigned char *req_sig = new unsigned char[65];

    memset(req_msg, 0x00, sizeof(message));
    memset(req_sig, 0x00, 65);

    ecall_create_ag_req_msg(global_eid, payment_num, payment_size, channel_ids, amount, req_msg, req_sig);

    *original_msg = req_msg;
    *output = req_sig;

    // printf("====== GENERATED AGREEMENT REQUEST MESSAGE ======\n");
    // printf("payment number: %d\n", payment_num);
    // printf("payment size: %d\n", payment_size);
    // printf("channel ids: ");
    // for(int i = 0; i < payment_size; i++)
    //     printf("%d ", channel_ids[i]);
    // printf("\n");
    // printf("amounts: ");
    // for(int i = 0; i < payment_size; i++)
    //     printf("%d ", amount[i]);
    // printf("\n");
    // printf("=================================================\n");

    // message *m = (message*)req_msg;
    // printf("===== AGREEMENT REQUEST MESSAGE BYTESTREAM ======\n");
    // printf("type: %d\n", m->type);
    // printf("channel_id: %d\n", m->channel_id);
    // printf("amount: %d\n", m->amount);
    // printf("counter: %d\n", m->counter);
    // printf("payment number: %d\n", m->payment_num);
    // printf("payment size: %d\n", m->payment_size);
    // printf("channel ids: ");
    // for(int i = 0; i < m->payment_size; i++)
    //     printf("%d ", m->channel_ids[i]);
    // printf("\n");
    // printf("amounts: ");
    // for(int i = 0; i < m->payment_size; i++)
    //     printf("%d ", m->payment_amount[i]);
    // printf("\n");
    // printf("=================================================\n");
}


void ecall_create_ud_req_msg_w(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *req_msg = new unsigned char[sizeof(message)];
    unsigned char *req_sig = new unsigned char[65];

    memset(req_msg, 0x00, sizeof(message));
    memset(req_sig, 0x00, 65);

    ecall_create_ud_req_msg(global_eid, payment_num, payment_size, channel_ids, amount, req_msg, req_sig);

    *original_msg = req_msg;
    *output = req_sig;
}


void ecall_create_confirm_msg_w(unsigned int payment_num, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *confirm_msg = new unsigned char[sizeof(message)];
    unsigned char *confirm_sig = new unsigned char[65];

    memset(confirm_msg, 0x00, sizeof(message));
    memset(confirm_sig, 0x00, 65);

    ecall_create_confirm_msg(global_eid, payment_num, confirm_msg, confirm_sig);

    *original_msg = confirm_msg;
    *output = confirm_sig;
}


unsigned int ecall_verify_ag_res_msg_w(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig)
{
    unsigned int is_verified;

    ecall_verify_ag_res_msg(global_eid, pubaddr, res_msg, res_sig, &is_verified);

    return is_verified;
}


unsigned int ecall_verify_ud_res_msg_w(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig)
{
    unsigned int is_verified;

    ecall_verify_ud_res_msg(global_eid, pubaddr, res_msg, res_sig, &is_verified);

    return is_verified;
}

/*
 *
 *
 * InstaPay 3.0
 */

unsigned int ecall_cross_accept_request_w(
		unsigned char *chain1Sender, 
		unsigned char *chain1MiddleMan, 
		unsigned char *chain1Receiver, 
		unsigned int chain1Amount, 
		unsigned char *chain2Sender, 
		unsigned char *chain2MiddleMan, 
		unsigned char *chain2Receiver, 
		unsigned int chain2Amount,
		unsigned char *chain3Sender, 
		unsigned char *chain3MiddleMan, 
		unsigned char *chain3Receiver, 
		unsigned int chain3Amount,
		unsigned int numOfParticipants)

{
    unsigned int payment_num;

    rwMutex.lock();
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
    ret =    ecall_cross_accept_request(global_eid, chain1Sender, chain1MiddleMan, chain1Receiver, chain1Amount, chain2Sender, chain2MiddleMan, chain2Receiver, chain2Amount, numOfParticipants, &payment_num);
    rwMutex.unlock();

    if (ret != SGX_SUCCESS) {
	 print_error_message(ret);
	 return 999999;
    }

    return payment_num;
}

void ecall_initSecp256k1CTX_w()
{
   ecall_initSecp256k1CTX(global_eid);
}

void ecall_cross_add_participant_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_cross_add_participant(global_eid, payment_num, addr);
}

void ecall_cross_update_preparedServer_list_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_cross_update_preparedServer_list(global_eid, payment_num, addr);
}

void ecall_cross_update_committedServer_list_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_cross_update_committedServer_list(global_eid, payment_num, addr);
}

unsigned int ecall_cross_check_prepared_unanimity_w(unsigned int payment_num, int which_list)
{
    unsigned int is_unanimous;

    ecall_cross_check_prepared_unanimity(global_eid, payment_num, which_list, &is_unanimous);

    return is_unanimous;
}

unsigned int ecall_cross_check_committed_unanimity_w(unsigned int payment_num, int which_list)
{
    unsigned int is_unanimous;

    ecall_cross_check_committed_unanimity(global_eid, payment_num, which_list, &is_unanimous);

    return is_unanimous;
}

unsigned int ecall_cross_create_all_prepare_req_msg_w(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char **original_msg, unsigned char **output)
{
	unsigned char *req_msg = new unsigned char[sizeof(cross_message)];
    	unsigned char *req_sig = new unsigned char[65];
    	unsigned int result = 1;

	memset(req_msg, 0x00, sizeof(cross_message));
	memset(req_sig, 0x00, 65);

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
	ret = ecall_cross_create_all_prepare_req_msg(global_eid, payment_num, sender, middleMan, receiver, sender_payment_size, sender_channel_ids, middleMan_payment_size, middleMan_channel_ids, receiver_payment_size, receiver_channel_ids, sender_amount, middleMan_amount, receiver_amount, req_msg, req_sig, &result);
		    
	if (ret != SGX_SUCCESS) {
//		print_error_message(ret);
		return 1;
	}

	*original_msg = req_msg;
	*output = req_sig;
	
	return result;
}

unsigned int ecall_cross_create_all_prepare_req_msg_w2(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned char *receiver2, unsigned char *receiver3, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, unsigned int receiver2_payment_size, unsigned int *receiver2_channel_ids, unsigned int receiver3_payment_size, unsigned int *receiver3_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char **original_msg, unsigned char **output)
{
	unsigned char *req_msg = NULL;// = new unsigned char[sizeof(cross_message)];
    	unsigned char *req_sig = new unsigned char[65];
    	unsigned int result = 1;

	//memset(req_msg, 0x00, sizeof(cross_message));
	memset(req_sig, 0x00, 65);

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
	ret = ecall_cross_create_all_prepare_req_msg2(global_eid, payment_num, sender, middleMan, receiver, receiver2, receiver3, sender_payment_size, sender_channel_ids, middleMan_payment_size, middleMan_channel_ids, receiver_payment_size, receiver_channel_ids, receiver2_payment_size, receiver2_channel_ids, receiver3_payment_size, receiver3_channel_ids, sender_amount, middleMan_amount, receiver_amount, &req_msg, req_sig, &result);
		    
	if (ret != SGX_SUCCESS) {
//		print_error_message(ret);
		return 1;
	}

	*original_msg = req_msg;
	*output = req_sig;
	return result;
}

unsigned int ecall_cross_verify_all_prepared_res_msg_w(unsigned char *res_msg, unsigned char *res_sig, unsigned char *address)
{
    unsigned int is_verified;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;    

    ret = ecall_cross_verify_all_prepared_res_msg(global_eid, res_msg, res_sig, address, &is_verified);
    if (ret != SGX_SUCCESS) {
//	    print_error_message(ret);
	    return 1;
    }
 
    return is_verified;
}

unsigned int ecall_cross_create_all_commit_req_msg_w(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char **original_msg, unsigned char **output)
{
	unsigned char *req_msg = new unsigned char[sizeof(cross_message)];
    	unsigned char *req_sig = new unsigned char[65];
    	unsigned int result = 1;

	memset(req_msg, 0x00, sizeof(cross_message));
	memset(req_sig, 0x00, 65);

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
	ret = ecall_cross_create_all_commit_req_msg(global_eid, payment_num, sender, middleMan, receiver, sender_payment_size, sender_channel_ids, middleMan_payment_size, middleMan_channel_ids, receiver_payment_size, receiver_channel_ids, sender_amount, middleMan_amount, receiver_amount, req_msg, req_sig, &result);
		    
	if (ret != SGX_SUCCESS) {
//		print_error_message(ret);
		return 1;
	}

	*original_msg = req_msg;
	*output = req_sig;

	return result;
}

unsigned int ecall_cross_create_all_commit_req_msg_w2(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned char *receiver2, unsigned char *receiver3, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, unsigned int receiver2_payment_size, unsigned int *receiver2_channel_ids, unsigned int receiver3_payment_size, unsigned int *receiver3_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char **original_msg, unsigned char **output)
{
	unsigned char *req_msg = NULL;// = new unsigned char[sizeof(cross_message)];
    	unsigned char *req_sig = new unsigned char[65];
    	unsigned int result = 1;

	//memset(req_msg, 0x00, sizeof(cross_message));
	memset(req_sig, 0x00, 65);

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
	ret = ecall_cross_create_all_commit_req_msg2(global_eid, payment_num, sender, middleMan, receiver, receiver2, receiver3, sender_payment_size, sender_channel_ids, middleMan_payment_size, middleMan_channel_ids, receiver_payment_size, receiver_channel_ids, receiver2_payment_size, receiver2_channel_ids, receiver3_payment_size, receiver3_channel_ids, sender_amount, middleMan_amount, receiver_amount, &req_msg, req_sig, &result);
		    
	if (ret != SGX_SUCCESS) {
//		print_error_message(ret);
		return 1;
	}

	*original_msg = req_msg;
	*output = req_sig;
	return result;
}

unsigned int ecall_cross_verify_all_committed_res_msg_w(unsigned char *res_msg, unsigned char *res_sig, unsigned char *address)
{
    unsigned int is_verified;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;    

    ret = ecall_cross_verify_all_committed_res_msg(global_eid, res_msg, res_sig, address, &is_verified);
    if (ret != SGX_SUCCESS) {
//	    print_error_message(ret);
	    return 1;
    }

    return is_verified;
}

unsigned int ecall_cross_create_all_confirm_req_msg_w(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char **original_msg, unsigned char **output)
{
	unsigned char *req_msg = new unsigned char[sizeof(cross_message)];
    	unsigned char *req_sig = new unsigned char[65];
    	unsigned int result = 1;

	memset(req_msg, 0x00, sizeof(cross_message));
	memset(req_sig, 0x00, 65);

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
	ret = ecall_cross_create_all_confirm_req_msg(global_eid, payment_num, sender, middleMan, receiver, sender_payment_size, sender_channel_ids, middleMan_payment_size, middleMan_channel_ids, receiver_payment_size, receiver_channel_ids, sender_amount, middleMan_amount, receiver_amount, req_msg, req_sig, &result);
		    
	if (ret != SGX_SUCCESS) {
//		print_error_message(ret);
		return 1;
	}

	*original_msg = req_msg;
	*output = req_sig;

	return result;
}

unsigned int ecall_cross_create_all_confirm_req_msg_w2(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned char *receiver2, unsigned char *receiver3, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, unsigned int receiver2_payment_size, unsigned int *receiver2_channel_ids, unsigned int receiver3_payment_size, unsigned int *receiver3_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char **original_msg, unsigned char **output)
{
	unsigned char *req_msg = NULL;// = new unsigned char[sizeof(cross_message)];
    	unsigned char *req_sig = new unsigned char[65];
    	unsigned int result = 1;

	//memset(req_msg, 0x00, sizeof(cross_message));
	memset(req_sig, 0x00, 65);

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;    
	ret = ecall_cross_create_all_confirm_req_msg2(global_eid, payment_num, sender, middleMan, receiver, receiver2, receiver3, sender_payment_size, sender_channel_ids, middleMan_payment_size, middleMan_channel_ids, receiver_payment_size, receiver_channel_ids, receiver2_payment_size, receiver2_channel_ids, receiver3_payment_size, receiver3_channel_ids, sender_amount, middleMan_amount, receiver_amount, &req_msg, req_sig, &result);
		    
	if (ret != SGX_SUCCESS) {
//		print_error_message(ret);
		return 1;
	}

	*original_msg = req_msg;
	*output = req_sig;
	return result;
}

void ecall_cross_create_all_refund_req_msg_w(unsigned int payment_num, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *refund_msg = new unsigned char[sizeof(message)];
    unsigned char *refund_sig = new unsigned char[65];

    memset(refund_msg, 0x00, sizeof(message));
    memset(refund_sig, 0x00, 65);

    ecall_cross_create_all_refund_req_msg(global_eid, payment_num, refund_msg, refund_sig);

    *original_msg = refund_msg;
    *output = refund_sig;
}

