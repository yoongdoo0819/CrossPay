#include "enclave.h"
#include "enclave_t.h"

#include <payment.h>
#include <message.h>


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