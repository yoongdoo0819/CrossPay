#include "app.h"
#include "enclave_u.h"


unsigned int ecall_accept_request_w(unsigned char *sender, unsigned char *receiver, unsigned int amount)
{
    unsigned int payment_num;

    ecall_accept_request(global_eid, sender, receiver, amount, &payment_num);

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

void ecall_cross_accept_request_w(unsigned char *sender, unsigned char *receiver, unsigned int amount, unsigned int payment_num)
{
    //unsigned int payment_num;

    ecall_cross_accept_request(global_eid, sender, receiver, amount, payment_num);

    //return payment_num;
}


void ecall_cross_add_participant_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_cross_add_participant(global_eid, payment_num, addr);
}


void ecall_cross_update_sentagr_list_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_cross_update_sentagr_list(global_eid, payment_num, addr);
}

void ecall_cross_update_sentupt_list_w(unsigned int payment_num, unsigned char *addr)
{
    ecall_cross_update_sentupt_list(global_eid, payment_num, addr);
}


int ecall_cross_check_unanimity_w(unsigned int payment_num, int which_list)
{
    int is_unanimous;

    ecall_cross_check_unanimity(global_eid, payment_num, which_list, &is_unanimous);

    return is_unanimous;
}


void ecall_cross_update_payment_status_to_success_w(unsigned int payment_num)
{
    ecall_cross_update_payment_status_to_success(global_eid, payment_num);
}


void ecall_cross_create_ag_req_msg_w(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *req_msg = new unsigned char[sizeof(message)];
    unsigned char *req_sig = new unsigned char[65];

    memset(req_msg, 0x00, sizeof(message));
    memset(req_sig, 0x00, 65);

    ecall_cross_create_ag_req_msg(global_eid, payment_num, payment_size, channel_ids, amount, req_msg, req_sig);

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


void ecall_cross_create_ud_req_msg_w(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *req_msg = new unsigned char[sizeof(message)];
    unsigned char *req_sig = new unsigned char[65];

    memset(req_msg, 0x00, sizeof(message));
    memset(req_sig, 0x00, 65);

    ecall_cross_create_ud_req_msg(global_eid, payment_num, payment_size, channel_ids, amount, req_msg, req_sig);

    *original_msg = req_msg;
    *output = req_sig;
}


void ecall_cross_create_confirm_msg_w(unsigned int payment_num, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *confirm_msg = new unsigned char[sizeof(message)];
    unsigned char *confirm_sig = new unsigned char[65];

    memset(confirm_msg, 0x00, sizeof(message));
    memset(confirm_sig, 0x00, 65);

    ecall_cross_create_confirm_msg(global_eid, payment_num, confirm_msg, confirm_sig);

    *original_msg = confirm_msg;
    *output = confirm_sig;
}


unsigned int ecall_cross_verify_ag_res_msg_w(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig)
{
    unsigned int is_verified;

    ecall_cross_verify_ag_res_msg(global_eid, pubaddr, res_msg, res_sig, &is_verified);

    return is_verified;
}


unsigned int ecall_cross_verify_ud_res_msg_w(unsigned char *pubaddr, unsigned char *res_msg, unsigned char *res_sig)
{
    unsigned int is_verified;

    ecall_cross_verify_ud_res_msg(global_eid, pubaddr, res_msg, res_sig, &is_verified);

    return is_verified;
}
