#include "enclave.h"
#include "enclave_t.h"

#include <payment.h>
#include <message.h>
#include <cross_message.h>
#include <cross_payment.h>

unsigned int Payment::acc_payment_num = 1;


void ecall_accept_request(unsigned char *sender, unsigned char *receiver, unsigned int amount, unsigned int *payment_num)
{
    payments.insert(map_payment_value(Payment::acc_payment_num, Payment(Payment::acc_payment_num, sender, receiver, amount)));
    *payment_num = Payment::acc_payment_num;
    Payment::acc_payment_num++;
}


void ecall_add_participant(unsigned int payment_num, unsigned char *addr)
{
    payments.find(payment_num)->second.register_participant(addr);
}


void ecall_update_sentagr_list(unsigned int payment_num, unsigned char *addr)
{
    payments.find(payment_num)->second.update_addrs_sent_agr(addr);
}


void ecall_update_sentupt_list(unsigned int payment_num, unsigned char *addr)
{
    payments.find(payment_num)->second.update_addrs_sent_upt(addr);
}


void ecall_check_unanimity(unsigned int payment_num, int which_list, int *is_unanimous)
{
    *is_unanimous = payments.find(payment_num)->second.check_unanimity(which_list);
}


void ecall_update_payment_status_to_success(unsigned int payment_num)
{
    payments.find(payment_num)->second.update_status_to_success();
}


void ecall_create_ag_req_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *req_msg, unsigned char *req_sig)
{
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Message));

    /* create agreement request message */

    request.type = AG_REQ;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);

    sign_message((unsigned char*)&request, sizeof(Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Message));
    memcpy(req_sig, req_signature, 65);

    return;
}


void ecall_create_ud_req_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *req_msg, unsigned char *req_sig)
{
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Message));

    /* create update request message */

    request.type = UD_REQ;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);

    sign_message((unsigned char*)&request, sizeof(Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Message));
    memcpy(req_sig, req_signature, 65);

    return;
}


void ecall_create_confirm_msg(unsigned int payment_num, unsigned char *confirm_msg, unsigned char *confirm_sig)
{
    unsigned char confirm_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Message confirm;

    memset((unsigned char*)&confirm, 0x00, sizeof(Message));

    /* create payment confirm message */

    confirm.type = CONFIRM;
    confirm.payment_num = payment_num;

    sign_message((unsigned char*)&confirm, sizeof(Message), seckey, confirm_signature);

    memcpy(confirm_msg, (unsigned char*)&confirm, sizeof(Message));
    memcpy(confirm_sig, confirm_signature, 65);

    return;
}


void ecall_verify_ag_res_msg(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Message *res = (Message*)res_msg;

    /* step 1. verify signature */

    if(verify_message(0, res_sig, res_msg, sizeof(Message), pubaddr)) {
        *is_verified = 0;
        return;
    }

    /* step 2. check that message type is 'AG_RES' */

    if(res->type != AG_RES || res->e != 1) {
        *is_verified = 0;
        return;
    }

    /* step 3. mark as verified */

    *is_verified = 1;
    return;
}


void ecall_verify_ud_res_msg(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Message *res = (Message*)res_msg;

    /* step 1. verify signature */

    if(verify_message(0, res_sig, res_msg, sizeof(Message), pubaddr)) {
        *is_verified = 0;
        return;
    }

    /* step 2. check that message type is 'UD_RES' */

    if(res->type != UD_RES) {
        *is_verified = 0;
        return;
    }

    /* step 3. mark as verified */

    *is_verified = 1;
    return;
}

/*
 *
 *
 * InstaPay 3.0
 */

void ecall_cross_accept_request( 
            unsigned char *chain1Server,
            unsigned char *chain1Sender, 
            unsigned char *chain1Receiver, 
            unsigned int chain1Amount,
            unsigned char *chain2Server,
            unsigned char *chain2Sender, 
            unsigned char *chain2Receiver, 
            unsigned int chain2Amount,
            unsigned int *payment_num)
{

    //Cross_Payment a = Cross_Payment();

    Cross_Payment cross_payment = Cross_Payment(1/*Cross_Payment::acc_cross_payment_num*/, chain1Server, chain1Sender, chain1Receiver, chain1Amount, chain2Server, chain2Sender, chain2Receiver, chain2Amount);

    cross_payments.insert(map_cross_payment_value(1, cross_payment));
    *payment_num = 1;
    
//    cross_payments.insert(map_cross_payment_value(Cross_Payment::acc_cross_payment_num, Cross_Payment(Cross_Payment::acc_cross_payment_num, chain1Server, chain1Sender, chain1Receiver, chain1Amount, chain2Server, chain2Sender, chain2Receiver, chain2Amount)));
    //*payment_num = Cross_Payment::acc_cross_payment_num;
    //Cross_Payment::acc_cross_payment_num++;
//    payments.insert(map_payment_value(Payment::acc_payment_num, Payment(Payment::acc_payment_num, sender, receiver, amount)));
 //   *payment_num = Payment::acc_payment_num;
  //  Payment::acc_payment_num++;
}       

void ecall_cross_add_participant(unsigned int payment_num, unsigned char *addr)
{
   
    //cross_payments.find(payment_num)->second.register_participant(addr);
}

void ecall_cross_update_preparedServer_list(unsigned int payment_num, unsigned char *addr)
{
    cross_payments.find(payment_num)->second.update_preparedServer(addr);
}

void ecall_cross_update_committedServer_list(unsigned int payment_num, unsigned char *addr)
{
    cross_payments.find(payment_num)->second.update_committedServer(addr);
}

void ecall_cross_check_prepared_unanimity(unsigned int payment_num, int which_list, unsigned int *is_unanimous)
{

    if (cross_payments.find(payment_num)->second.m_chain1Server_prepared == 1) {
	    cross_payments.find(payment_num)->second.m_cross_status = PREPARED;
	    ocall_print_string((const char*)"Status : PREPARED \n");
	    *is_unanimous = 1;
    }
    else {
	    ocall_print_string((const char*)"Status : NONE \n");
	    *is_unanimous = 0;
    }
    //*is_unanimous = cross_payments.find(payment_num)->second.check_unanimity(which_list);
}

void ecall_cross_check_committed_unanimity(unsigned int payment_num, int which_list, unsigned int *is_unanimous)
{
    if (cross_payments.find(payment_num)->second.m_chain1Server_committed == 1) {
	    cross_payments.find(payment_num)->second.m_cross_status = COMMITTED;
	    ocall_print_string((const char*)"Status : COMMITTED \n");
	    *is_unanimous = 1;
    }
    else
	    *is_unanimous = 0;
    //*is_unanimous = cross_payments.find(payment_num)->second.check_unanimity(which_list);
}



void ecall_cross_create_all_prepare_req_msg(unsigned int payment_num, unsigned char *req_msg, unsigned char *req_sig)
{
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Cross_Message));

    /* create cross all prepare request message */
    
    request.type = CROSS_ALL_PREPARE_REQ;
    request.payment_num = payment_num;
    //request.payment_size = payment_size;
    //memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    //memcpy(request.payment_amount, amount, sizeof(int) * payment_size);

    sign_message((unsigned char*)&request, sizeof(Cross_Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Cross_Message));
    memcpy(req_sig, req_signature, 65);

    return;
}

void ecall_cross_verify_all_prepared_res_msg(unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Cross_Message *res = (Cross_Message*)res_msg;
    ocall_print_string((const char*)"verification of all prepared msg");

    /* step 1. verify signature */
/*
    if(verify_message(1, res_sig, res_msg, sizeof(Cross_Message), NULL)) {
        *is_verified = 0;
	printf("prepared msg verification failure");
        return;
    }
*/
    /* step 2. check that message type is 'AG_RES' */

    if(res->type != CROSS_ALL_PREPARED) {// || res->e != 1) {
        *is_verified = 0;
	printf("prepared msg type failure");
        return;
    }

    if(res->server == chain1Server) {
	    cross_payments.find(res->payment_num)->second.m_chain1Server_prepared = 1;
    }
    else if(res->server == chain2Server)
	    cross_payments.find(res->payment_num)->second.m_chain2Server_prepared = 1;

    /* step 3. mark as verified */

    //ecall_cross_update_preparedServer_list(res->payment_num, res->server);
    //cross_payments.find((res->payment_num))->second.update_preparedServer(res->server);

    *is_verified = 1;
//    printf("participants : %s \n", cross_payments.find((res->payment_num))->m_participants);
     ocall_print_string((const char*)"verification end of all prepared msg");
   
    return;
}

void ecall_cross_create_all_commit_req_msg(unsigned int payment_num, unsigned char *req_msg, unsigned char *req_sig)
{
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Cross_Message));

    /* create update request message */

    request.type = CROSS_ALL_COMMIT_REQ;
    request.payment_num = payment_num;
    //request.payment_size = payment_size;
    //memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    //memcpy(request.payment_amount, amount, sizeof(int) * payment_size);

    sign_message((unsigned char*)&request, sizeof(Cross_Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Cross_Message));
    memcpy(req_sig, req_signature, 65);

    return;
}

void ecall_cross_verify_all_committed_res_msg(unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Cross_Message *res = (Cross_Message*)res_msg;

    /* step 1. verify signature */
/*
    if(verify_message(1, res_sig, res_msg, sizeof(Message), NULL)) {
        *is_verified = 0;
	ocall_print_string("verify failure");
        return;
    }
*/
    /* step 2. check that message type is 'AG_RES' */

    if(res->type != CROSS_ALL_COMMITTED) {// || res->e != 1) {
        *is_verified = 0;
        return;
    }

    if(res->server == chain1Server)
	    cross_payments.find(res->payment_num)->second.m_chain1Server_committed = 1;
    else if(res->server == chain2Server)
	    cross_payments.find(res->payment_num)->second.m_chain2Server_committed = 1;

    /* step 3. mark as verified */

    *is_verified = 1;
    return;
}


void ecall_cross_create_all_confirm_req_msg(unsigned int payment_num, unsigned char *confirm_msg, unsigned char *confirm_sig)
{
    unsigned char confirm_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message confirm;

    memset((unsigned char*)&confirm, 0x00, sizeof(Cross_Message));

    /* create payment confirm message */
    
    confirm.type = CROSS_ALL_CONFIRM_REQ;
    confirm.payment_num = payment_num;

    sign_message((unsigned char*)&confirm, sizeof(Cross_Message), seckey, confirm_signature);

    memcpy(confirm_msg, (unsigned char*)&confirm, sizeof(Cross_Message));
    memcpy(confirm_sig, confirm_signature, 65);

    return;
}

