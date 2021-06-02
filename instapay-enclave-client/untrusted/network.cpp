#include "app.h"
#include "enclave_u.h"

#include <string.h>
#include <mutex>

std::mutex rwMutex;

void ecall_go_pre_update_two_w(unsigned int payment_num)
{
    //ecall_accept_payments(global_eid, payment_num);
    ecall_go_pre_update_two(global_eid, payment_num);
}

unsigned int ecall_go_pre_update_w(unsigned char *msg, unsigned char *signature, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message_res)];
    unsigned char *reply_sig = new unsigned char[65];

    memset(reply_msg, 0x00, sizeof(message_res));
    memset(reply_sig, 0x00, 65);
/*
    rwMutex.lock();
    ecall_go_post_update_two(global_eid, msg, signature, reply_msg, reply_sig);
    rwMutex.unlock();
*/
    unsigned int result = 1;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_go_pre_update(global_eid, msg, signature, reply_msg, reply_sig, &result);

    if (ret != SGX_SUCCESS) {
//	    printf("AG SGX FAILURE \n");
	    result = 2;
    }

    *original_msg = reply_msg;
    *output = reply_sig;

    //result = 9999;
    return result;
}

unsigned int ecall_go_post_update_w(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char *crossServerSig,  unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message_res)];
    unsigned char *reply_sig = new unsigned char[65];

    memset(reply_msg, 0x00, sizeof(message_res));
    memset(reply_sig, 0x00, 65);

//    rwMutex.lock();
//    ecall_go_post_update_two(global_eid, msg, signature, reply_msg, reply_sig);
//    rwMutex.unlock();

    unsigned int result = 1;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_go_post_update(global_eid, msg, signature, senderMSG, senderSig, middleManMSG, middleManSig, receiverMSG, receiverSig, crossServerMSG, crossServerSig, reply_msg, reply_sig, &result); 

    if (ret != SGX_SUCCESS) {
//	    printf("UD SGX FAILURE \n");

	    result = 2;
    }

    *original_msg = reply_msg;
    *output = reply_sig;


    return result;
}


unsigned int ecall_go_idle_w(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char *crossServerSig)
{


//    rwMutex.lock();
//    ecall_go_post_update_two(global_eid, msg, signature, NULL, NULL);    
//    rwMutex.unlock();

//    rwMutex.lock();

    unsigned int result = 1;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_go_idle(global_eid, msg, signature, senderMSG, senderSig, middleManMSG, middleManSig, receiverMSG, receiverSig, crossServerMSG, crossServerSig, &result);    

    if (ret != SGX_SUCCESS) {
//	    printf("CF SGX FAILURE \n");

	    result = 2;
    }


    return result;
//    rwMutex.unlock();
}


void ecall_register_comminfo_w(unsigned int channel_id, unsigned char *ip, unsigned int port)
{
    ecall_register_comminfo(global_eid, channel_id, ip, strlen((char*)ip), port);
}

/*
 *
 *
 * InstaPay 3.0
 */

unsigned int ecall_cross_go_pre_update_w(unsigned char *msg, unsigned char *signature, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message_res)];
    unsigned char *reply_sig = new unsigned char[65];
    unsigned int result = 1;

    memset(reply_msg, 0x00, sizeof(message_res));
    memset(reply_sig, 0x00, 65);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_cross_go_pre_update(global_eid, msg, signature, reply_msg, reply_sig, &result);

    if (ret != SGX_SUCCESS) {
//	    printf("AG SGX FAILURE \n");
	    result = 2;
    }

    *original_msg = reply_msg;
    *output = reply_sig;

    return result;
}

unsigned int ecall_cross_go_post_update_w(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char *crossServerSig,  unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message_res)];
    unsigned char *reply_sig = new unsigned char[65];
    unsigned int result = 1;

    memset(reply_msg, 0x00, sizeof(message_res));
    memset(reply_sig, 0x00, 65);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_cross_go_post_update(global_eid, msg, signature, senderMSG, senderSig, middleManMSG, middleManSig, receiverMSG, receiverSig, crossServerMSG, crossServerSig, reply_msg, reply_sig, &result);

    if (ret != SGX_SUCCESS) {
//	    printf("AG SGX FAILURE \n");
	    result = 2;
    }

    *original_msg = reply_msg;
    *output = reply_sig;

    return result;
}

unsigned int ecall_cross_go_idle_w(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char *crossServerSig)
{
	unsigned int result = 1;

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_cross_go_idle(global_eid, msg, signature, senderMSG, senderSig, middleManMSG, middleManSig, receiverMSG, receiverSig, crossServerMSG, crossServerSig, &result);

	if (ret != SGX_SUCCESS) {
//	    printf("AG SGX FAILURE \n");
	    result = 2;
	 }

	return result;
}

void ecall_cross_refund_w(unsigned char *msg, unsigned char *signature)
{
    ecall_cross_refund(global_eid, msg, signature);    
}

