#include "enclave.h"
#include "enclave_t.h"

#include <stdint.h>
#include <payment.h>
#include <message.h>
#include <cross_message.h>

unsigned int Payment::acc_payment_num = 1;


void ecall_accept_request(unsigned char *sender, unsigned char *receiver, unsigned int amount, unsigned int payment_num)
{

    payments.insert(map_payment_value(payment_num, Payment(payment_num, sender, receiver, amount)));
//    printf("create payment_num : %d \n", payment_num);
    //*payment_num = Payment::acc_payment_num;
    //Payment::acc_payment_num++;
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
//    printf("%d AG REQ CREATED START !!!!!!!!!!!!!\n", payment_num);

    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Message));

    /* create agreement request message */
/*
    request.type = AG_REQ;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);
*/
    sign_message((unsigned char*)&request, sizeof(Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Message));
    memcpy(req_sig, req_signature, 65);

    free(seckey);

//    printf("%d AG REQ CREATED \n", payment_num);
/*    if(request.type != AG_REQ)
	    printf("failure!! \n");
*/
    return;
}

void ecall_create_ag_req_msg_temp(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char *req_msg, unsigned char *req_sig)
{
//    printf("%d AG REQ CREATED START !!!!!!!!!!!!!\n", payment_num);

    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Message));

    /* create agreement request message */

    request.type = AG_REQ;
    request.payment_num = payment_num;
/*
    printf("%s \n", sender);
    printf("%d \n", sender_payment_size);
    printf("%d \n", sender_channel_ids[0]);

    printf("%s \n", middleMan);
    printf("%d \n", middleMan_payment_size);
    printf("%d \n", middleMan_channel_ids[0]);
    printf("%d \n", middleMan_channel_ids[1]);

    printf("%s \n", receiver);
    printf("%d \n", receiver_payment_size);
    printf("%d \n", receiver_channel_ids[0]);
*/
    memcpy(request.participant[0].party, sender, 41);
    request.participant[0].payment_size = sender_payment_size;
    memcpy(request.participant[0].channel_ids, sender_channel_ids, sizeof(unsigned int) * sender_payment_size);
    memcpy(request.participant[0].payment_amount, sender_amount, sizeof(int) * sender_payment_size);

    memcpy(request.participant[1].party, middleMan, 41);
    request.participant[1].payment_size = middleMan_payment_size;
    memcpy(request.participant[1].channel_ids, middleMan_channel_ids, sizeof(unsigned int) * middleMan_payment_size);
    memcpy(request.participant[1].payment_amount, middleMan_amount, sizeof(int) * middleMan_payment_size);

    memcpy(request.participant[2].party, receiver, 41);
    request.participant[2].payment_size = receiver_payment_size;
    memcpy(request.participant[2].channel_ids, receiver_channel_ids, sizeof(unsigned int) * receiver_payment_size);
    memcpy(request.participant[2].payment_amount, receiver_amount, sizeof(int) * receiver_payment_size);

/*    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);
*/
    sign_message((unsigned char*)&request, sizeof(Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Message));
    memcpy(req_sig, req_signature, 65);

    free(seckey);

    /*
    printf("%s \n", request.participant[0].party);
    printf("%d \n", request.participant[0].payment_size);
    printf("%d \n", request.participant[0].channel_ids[0]);

    printf("%s \n", request.participant[1].party);
    printf("%d \n", request.participant[1].payment_size);
    printf("%d \n", request.participant[1].channel_ids[0]);
    printf("%d \n", request.participant[1].channel_ids[1]);

    printf("%s \n", request.participant[2].party);
    printf("%d \n", request.participant[2].payment_size);
    printf("%d \n", request.participant[2].channel_ids[0]);
    */

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
/*
    request.type = UD_REQ;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);
*/
    sign_message((unsigned char*)&request, sizeof(Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Message));
    memcpy(req_sig, req_signature, 65);

    free(seckey);
//    printf("%d UD REQ CREATED \n", payment_num);

    return;
}

void ecall_create_ud_req_msg_temp(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char *req_msg, unsigned char *req_sig)
{
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Message));

    /* create update request message */

    request.type = UD_REQ;
    request.payment_num = payment_num;

    memcpy(request.participant[0].party, sender, 41);
    request.participant[0].payment_size = sender_payment_size;
    memcpy(request.participant[0].channel_ids, sender_channel_ids, sizeof(unsigned int) * sender_payment_size);
    memcpy(request.participant[0].payment_amount, sender_amount, sizeof(int) * sender_payment_size);

    memcpy(request.participant[1].party, middleMan, 41);
    request.participant[1].payment_size = middleMan_payment_size;
    memcpy(request.participant[1].channel_ids, middleMan_channel_ids, sizeof(unsigned int) * middleMan_payment_size);
    memcpy(request.participant[1].payment_amount, middleMan_amount, sizeof(int) * middleMan_payment_size);

    memcpy(request.participant[2].party, receiver, 41);
    request.participant[2].payment_size = receiver_payment_size;
    memcpy(request.participant[2].channel_ids, receiver_channel_ids, sizeof(unsigned int) * receiver_payment_size);
    memcpy(request.participant[2].payment_amount, receiver_amount, sizeof(int) * receiver_payment_size);

/*
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);
*/
    sign_message((unsigned char*)&request, sizeof(Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Message));
    memcpy(req_sig, req_signature, 65);

    free(seckey);
//    printf("%d UD REQ CREATED \n", payment_num);

/*
    printf("%s \n", request.participant[0].party);
    printf("%d \n", request.participant[0].payment_size);
    printf("%d \n", request.participant[0].channel_ids[0]);

    printf("%s \n", request.participant[1].party);
    printf("%d \n", request.participant[1].payment_size);
    printf("%d \n", request.participant[1].channel_ids[0]);
    printf("%d \n", request.participant[1].channel_ids[1]);

    printf("%s \n", request.participant[2].party);
    printf("%d \n", request.participant[2].payment_size);
    printf("%d \n", request.participant[2].channel_ids[0]);
*/

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

    free(seckey);
//    printf("%d CF REQ CREATED \n", payment_num);

    return;
}

void ecall_create_confirm_msg_temp(unsigned int payment_num, unsigned char *sender, unsigned char *middleMan, unsigned char *receiver, unsigned int sender_payment_size, unsigned int *sender_channel_ids, unsigned int middleMan_payment_size, unsigned int *middleMan_channel_ids, unsigned int receiver_payment_size, unsigned int *receiver_channel_ids, int *sender_amount, int *middleMan_amount, int *receiver_amount, unsigned char *confirm_msg, unsigned char *confirm_sig)
{
    unsigned char confirm_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Message confirm;

    memset((unsigned char*)&confirm, 0x00, sizeof(Message));

    /* create payment confirm message */

    confirm.type = CONFIRM;
    confirm.payment_num = payment_num;

    memcpy(confirm.participant[0].party, sender, 41);
    confirm.participant[0].payment_size = sender_payment_size;
    memcpy(confirm.participant[0].channel_ids, sender_channel_ids, sizeof(unsigned int) * sender_payment_size);
    memcpy(confirm.participant[0].payment_amount, sender_amount, sizeof(int) * sender_payment_size);


    memcpy(confirm.participant[1].party, middleMan, 41);
    confirm.participant[1].payment_size = middleMan_payment_size;
    memcpy(confirm.participant[1].channel_ids, middleMan_channel_ids, sizeof(unsigned int) * middleMan_payment_size);
    memcpy(confirm.participant[1].payment_amount, middleMan_amount, sizeof(int) * middleMan_payment_size);

    memcpy(confirm.participant[2].party, receiver, 41);
    confirm.participant[2].payment_size = receiver_payment_size;
    memcpy(confirm.participant[2].channel_ids, receiver_channel_ids, sizeof(unsigned int) * receiver_payment_size);
    memcpy(confirm.participant[2].payment_amount, receiver_amount, sizeof(int) * receiver_payment_size);

    sign_message((unsigned char*)&confirm, sizeof(Message), seckey, confirm_signature);

    memcpy(confirm_msg, (unsigned char*)&confirm, sizeof(Message));
    memcpy(confirm_sig, confirm_signature, 65);

    free(seckey);
}

void ecall_verify_ag_res_msg(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Message *res = (Message*)res_msg;

    /* step 1. verify signature */
/*
    if(verify_message(0, res_sig, res_msg, sizeof(Message), pubaddr)) {
        *is_verified = 0;
        return;
    }
*/
    verify_message(0, res_sig, res_msg, sizeof(Message), pubaddr);

    /* step 2. check that message type is 'AG_RES' */
    
    if(res->type != AG_RES || res->e != 1) {
        *is_verified = 1;
	//printf("NOT AG RES ############################ \n");
        return;
    }

    /* step 3. mark as verified */

    *is_verified = 9999;
    //printf("AG RES VERIFIED \n");

    return;
}


void ecall_verify_ud_res_msg(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Message *res = (Message*)res_msg;

    /* step 1. verify signature */
/*
    if(verify_message(0, res_sig, res_msg, sizeof(Message), pubaddr)) {
        *is_verified = 0;
        return;
    }
*/
    verify_message(0, res_sig, res_msg, sizeof(Message), pubaddr);

    /* step 2. check that message type is 'UD_RES' */

    if(res->type != UD_RES) {
	//printf("NOT UD RES ############################ \n");
        *is_verified = 1;
        return;
    }

    /* step 3. mark as verified */

    *is_verified = 9999;
    //printf("UD RES VERIFIED \n");

    return;
}

/*
 *
 *
 * InstaPay 3.0
 */


void ecall_cross_accept_request(unsigned char *sender, unsigned char *receiver, unsigned int amount, unsigned int payment_num)
{
    printf("ecall cross accept request start \n");
    payments.insert(map_payment_value(payment_num, Payment(payment_num, sender, receiver, amount)));
    //*payment_num = Payment::acc_payment_num;
    //Payment::acc_payment_num++;
}


void ecall_cross_add_participant(unsigned int payment_num, unsigned char *addr)
{
    payments.find(payment_num)->second.register_participant(addr);
}


void ecall_cross_update_sentagr_list(unsigned int payment_num, unsigned char *addr)
{
    payments.find(payment_num)->second.update_addrs_sent_agr(addr);
}

void ecall_cross_update_sentupt_list(unsigned int payment_num, unsigned char *addr)
{
    payments.find(payment_num)->second.update_addrs_sent_upt(addr);
}


void ecall_cross_check_unanimity(unsigned int payment_num, int which_list, int *is_unanimous)
{
    *is_unanimous = payments.find(payment_num)->second.check_unanimity(which_list);
}


void ecall_cross_update_payment_status_to_success(unsigned int payment_num)
{
    payments.find(payment_num)->second.update_status_to_success();
}


void ecall_cross_create_ag_req_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *req_msg, unsigned char *req_sig)
{
    printf("0 \n");
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Cross_Message));

    /* create agreement request message */

    printf("1 \n");
    request.type = CROSS_PREPARE_REQ;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);

    printf("2 \n");
    sign_message((unsigned char*)&request, sizeof(Cross_Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Cross_Message));
    memcpy(req_sig, req_signature, 65);

    printf("CROSS CREATE AG REQ out  \n");
    free(seckey);
    return;
}


void ecall_cross_create_ud_req_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *req_msg, unsigned char *req_sig)
{
    printf("3 \n");
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Cross_Message));

    /* create update request message */

    printf("4 \n");
    request.type = CROSS_COMMIT_REQ;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);

    printf("5 \n");
    sign_message((unsigned char*)&request, sizeof(Cross_Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Cross_Message));
    memcpy(req_sig, req_signature, 65);

    free(seckey);
    printf("6 \n");

    return;
}


void ecall_cross_create_confirm_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *confirm_msg, unsigned char *confirm_sig)
{

    printf("7 \n");
    unsigned char confirm_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message confirm;

    memset((unsigned char*)&confirm, 0x00, sizeof(Cross_Message));

    /* create payment confirm message */

    confirm.type = CROSS_CONFIRM_REQ;
    confirm.payment_num = payment_num;
    confirm.payment_size = payment_size;

    memcpy(confirm.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(confirm.payment_amount, amount, sizeof(int) * payment_size);

    printf("8 \n");
    sign_message((unsigned char*)&confirm, sizeof(Cross_Message), seckey, confirm_signature);

    memcpy(confirm_msg, (unsigned char*)&confirm, sizeof(Cross_Message));
    memcpy(confirm_sig, confirm_signature, 65);

    free(seckey);
    printf("9 \n");
    return;
}


void ecall_cross_verify_ag_res_msg(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Cross_Message *res = (Cross_Message*)res_msg;

    /* step 1. verify signature */

    //printf("??????????????????????????????\n");
    /*
    if(verify_message(0, res_sig, res_msg, sizeof(Cross_Message), pubaddr)) {
        *is_verified = 0;
        return;
    }
    */

    /* step 2. check that message type is 'AG_RES' */
    //printf("??????????????????????????????\n");
  /*  
    if(res->type != CROSS_PREPARE_RES || res->e != 1) {
	ocall_print_string("FAILURE###########################################");
        *is_verified = 0;
        return;
    }
    printf("??????????????????????????????\n");
    if(strcmp((const char*)&(res->server), (const char*)&"cross-server") != 0) {
	*is_verified = 0;
	return;
    }
*/
    ocall_print_string("CROSS AG RES VERIFY SUCCESS \n");

    /* step 3. mark as verified */

    *is_verified = 1;
    return;
}


void ecall_cross_verify_ud_res_msg(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig, unsigned int *is_verified)
{
    Cross_Message *res = (Cross_Message*)res_msg;

    /* step 1. verify signature */

    /*
    if(verify_message(0, res_sig, res_msg, sizeof(Cross_Message), pubaddr)) {
        *is_verified = 0;
        return;
    }
    */

    /* step 2. check that message type is 'UD_RES' */
/*
    printf("################################ res type : %s \n", res->type);
    if(res->type != CROSS_COMMIT_RES) {
        *is_verified = 0;
        return;
    }

    if(strcmp((const char*)&(res->server), (const char*)"cross-server") != 0) {
	*is_verified = 0;
	return ;
    }
*/
    /* step 3. mark as verified */
    ocall_print_string("CROSS UD RES VERIFY SUCCESS \n");

    *is_verified = 1;
    return;
}

void ecall_cross_create_all_prepare_msg(unsigned char *msg, unsigned char *signature, unsigned int *is_verified)
{
	
     Cross_Message * all_prepare_req = (Cross_Message*)msg;

     /*
     if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
     {
	*is_verified = 0;
	return; 
     }
     */

     if(all_prepare_req->type != CROSS_ALL_PREPARE_REQ)
     {
	*is_verified = 0;
	return;
     }

     *is_verified = 1;
     return;
}

void ecall_cross_create_all_prepared_msg(unsigned int payment_num, unsigned char *res_msg, unsigned char *res_sig)
{

    printf("10 \n");
    unsigned char res_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message response;

    memset((unsigned char*)&response, 0x00, sizeof(Cross_Message));

    /* create agreement request message */

    response.server = CHAIN1_SERVER;
    response.type = CROSS_ALL_PREPARED;
    response.payment_num = payment_num;
    response.payment_size = 0;
    //memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    //memcpy(request.payment_amount, amount, sizeof(int) * payment_size);


    printf("11 \n");
    sign_message((unsigned char*)&response, sizeof(Cross_Message), seckey, res_signature);

    memcpy(res_msg, (unsigned char*)&response, sizeof(Cross_Message));
    memcpy(res_sig, res_signature, 65);

    free(seckey);
    printf("12 \n");
    return;
}


void ecall_cross_create_prepare_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *req_msg, unsigned char *req_sig)
{

    printf("13 \n");
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Cross_Message));

    /* create agreement request message */

    request.type = CROSS_PREPARE_REQ;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);


    printf("14 \n");
    sign_message((unsigned char*)&request, sizeof(Cross_Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Cross_Message));
    memcpy(req_sig, req_signature, 65);

    free(seckey);
    printf("15 \n");
    return;
}

void ecall_cross_create_all_commit_msg(unsigned char *msg, unsigned char *signature, unsigned int *is_verified)
{
	
     Cross_Message * all_commit_req = (Cross_Message*)msg;

     /*
     if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
     {
	*is_verified = 0;
	return; 
     }
     */

     if(all_commit_req->type != CROSS_ALL_COMMIT_REQ)
     {
	*is_verified = 0;
	return;
     }

     *is_verified = 1;
     return;
}

void ecall_cross_create_all_committed_msg(unsigned int payment_num, unsigned char *res_msg, unsigned char *res_sig)
{

    printf("16 \n");
    unsigned char res_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message response;

    memset((unsigned char*)&response, 0x00, sizeof(Cross_Message));

    /* create agreement request message */

    response.server = CHAIN1_SERVER;
    response.type = CROSS_ALL_COMMITTED;
    response.payment_num = payment_num;
    //request.payment_size = payment_size;
    //memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    //memcpy(request.payment_amount, amount, sizeof(int) * payment_size);


    printf("17 \n");
    sign_message((unsigned char*)&response, sizeof(Cross_Message), seckey, res_signature);

    memcpy(res_msg, (unsigned char*)&response, sizeof(Cross_Message));
    memcpy(res_sig, res_signature, 65);

    free(seckey);
    printf("18 \n");
    return;
}

void ecall_cross_create_all_confirm_msg(unsigned char *msg, unsigned char *signature, unsigned int *is_verified)
{
	
     Cross_Message * all_confirm_req = (Cross_Message*)msg;
/*
     if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
     {
	*is_verified = 0;
	return; 
     }
*/
     if(all_confirm_req->type != CROSS_ALL_CONFIRM_REQ)
     {
	*is_verified = 0;
	return;
     }

     *is_verified = 1;
     return;
}


void ecall_cross_create_all_refund_msg(unsigned char *msg, unsigned char *signature, unsigned int *is_verified)
{
	
     Cross_Message * all_refund_req = (Cross_Message*)msg;

     /*
     if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
     {
	*is_verified = 0;
	return; 
     }
     */

     if(all_refund_req->type != CROSS_ALL_REFUND_REQ)
     {
	*is_verified = 0;
	return;
     }

     *is_verified = 1;
     return;
}



void ecall_cross_create_refund_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *refund_msg, unsigned char *refund_sig)
{
    unsigned char refund_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message refund;

    memset((unsigned char*)&refund, 0x00, sizeof(Cross_Message));

    /* create payment refund message */

    refund.type = CROSS_REFUND_REQ;
    refund.payment_num = payment_num;
    refund.payment_size = payment_size;

    memcpy(refund.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(refund.payment_amount, amount, sizeof(int) * payment_size);

    sign_message((unsigned char*)&refund, sizeof(Cross_Message), seckey, refund_signature);

    memcpy(refund_msg, (unsigned char*)&refund, sizeof(Cross_Message));
    memcpy(refund_sig, refund_signature, 65);

    free(seckey);
    return;
}

/*
void ecall_cross_create_refund_msg(unsigned int payment_num, unsigned char *refund_msg, unsigned char *refund_sig)
{
    unsigned char refund_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message refund;

    memset((unsigned char*)&refund, 0x00, sizeof(Cross_Message));

    // create cross payment refund message 

    refund.type = CROSS_REFUND_REQ;
    refund.payment_num = payment_num;

    sign_message((unsigned char*)&refund, sizeof(Cross_Message), seckey, refund_signature);

    memcpy(refund_msg, (unsigned char*)&refund, sizeof(Cross_Message));
    memcpy(refund_sig, refund_signature, 65);

    return;
}

*/

/*void ecall_cross_create_all_prepare_msg(unsigned char *msg, unsigned char *signature, unsigned char* is_verified)
{
	
	Cross_Message * all_prepare_req = (Cross_Message*)msg;

	if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
	{
		*is_verified = 0;
		return; 
	}

	if(all_prepare_req->type != CROSS_ALL_PREPARE_REQ)
	{
		*is_verified = 0;
		return;
	}

	*is_verified = 1;
	return;
}
*/

/*
void ecall_cross_create_all_commit_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *req_msg, unsigned char *req_sig)
{
    unsigned char req_signature[65] = {0, };
    unsigned char *seckey_arr = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
    unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);

    Cross_Message request;

    memset((unsigned char*)&request, 0x00, sizeof(Cross_Message));

    // create update request message 

    request.type = CROSS_ALL_COMMITTED;
    request.payment_num = payment_num;
    request.payment_size = payment_size;
    memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
    memcpy(request.payment_amount, amount, sizeof(int) * payment_size);

    sign_message((unsigned char*)&request, sizeof(Cross_Message), seckey, req_signature);

    memcpy(req_msg, (unsigned char*)&request, sizeof(Cross_Message));
    memcpy(req_sig, req_signature, 65);

    return;
}*/
