#include "app.h"
#include "enclave_u.h"


void ecall_preset_account_w(unsigned char *addr, unsigned char *seckey)
{
    ecall_preset_account(global_eid, addr, seckey);
}


void ecall_preset_payment_w(unsigned int pn, unsigned int channel_id, int amount)
{
    ecall_preset_payment(global_eid, pn, channel_id, amount);
}


unsigned char* ecall_create_account_w(void)
{
    unsigned char *generated_addr = new unsigned char[20];

    ecall_create_account(global_eid, generated_addr);

    return generated_addr;
}


unsigned char* ecall_create_channel_w(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int deposit, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    printf("ECALL CREATE CHANNEL W START");
    ecall_create_channel(global_eid, nonce, owner, receiver, deposit, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;

    printf("ECALL CREATE CHANNEL W");
    return signed_tx;
}


unsigned char* ecall_onchain_payment_w(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int amount, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_onchain_payment(global_eid, nonce, owner, receiver, amount, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;
    
    return signed_tx;
}


unsigned int ecall_pay_w(unsigned int channel_id, unsigned int amount, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *msg = new unsigned char[sizeof(message)];
    unsigned char *signature = new unsigned char[65];

    int is_success;

    memset(msg, 0x00, sizeof(message));

    ecall_pay(global_eid, channel_id, amount, &is_success, msg, signature);
    *original_msg = msg;
    *output = signature;

    return is_success;
}


void ecall_paid_w(unsigned char *msg, unsigned char *signature, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message)];
    unsigned char *reply_sig = new unsigned char[65];

    memset(reply_msg, 0x00, sizeof(message));

    ecall_paid(global_eid, msg, signature, reply_msg, reply_sig);
    *original_msg = reply_msg;
    *output = reply_sig;
}


void ecall_pay_accepted_w(unsigned char *msg, unsigned char *signature)
{
    ecall_pay_accepted(global_eid, msg, signature);
}


int ecall_get_balance_w(unsigned int channel_id)
{
    unsigned int balance;

    ecall_get_balance(global_eid, channel_id, &balance);

    return balance;
}


void* ecall_get_channel_info_w(unsigned int channel_id)
{
    unsigned char *channel_info = new unsigned char[sizeof(channel)];

    ecall_get_channel_info(global_eid, channel_id, channel_info);

    return channel_info;
}


unsigned char* ecall_close_channel_w(unsigned int nonce, unsigned char *owner, unsigned int channel_id, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_close_channel(global_eid, nonce, owner, channel_id, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;
    
    return signed_tx;
}


unsigned char* ecall_eject_w(unsigned int nonce, unsigned int pn, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_eject(global_eid, nonce, pn, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;
    
    return signed_tx;
}


unsigned int ecall_get_num_open_channels_w(void)
{
    unsigned int num_open_channels;

    ecall_get_num_open_channels(global_eid, &num_open_channels);

    return num_open_channels;
}


void* ecall_get_open_channels_w(void)
{
    unsigned char *open_channels;
    unsigned int num_open_channels;

    ecall_get_num_open_channels(global_eid, &num_open_channels);
    open_channels = (unsigned char*)malloc(sizeof(channel) * num_open_channels);

    ecall_get_open_channels(global_eid, open_channels);

    return open_channels;
}


unsigned int ecall_get_num_closed_channels_w(void)
{
    unsigned int num_closed_channels;

    ecall_get_num_closed_channels(global_eid, &num_closed_channels);

    return num_closed_channels;
}


void* ecall_get_closed_channels_w(void)
{
    unsigned char *closed_channels;
    unsigned int num_closed_channels;

    ecall_get_num_closed_channels(global_eid, &num_closed_channels);
    closed_channels = (unsigned char*)malloc(sizeof(channel) * num_closed_channels);

    ecall_get_open_channels(global_eid, closed_channels);

    return closed_channels;
}


unsigned int ecall_get_num_public_addrs_w(void)
{
    unsigned int num_public_addrs;

    ecall_get_num_closed_channels(global_eid, &num_public_addrs);

    return num_public_addrs;
}


void* ecall_get_public_addrs_w(void)
{
    unsigned char *public_addrs;
    unsigned int num_public_addrs;

    ecall_get_num_public_addrs(global_eid, &num_public_addrs);
    public_addrs = (unsigned char*)malloc(sizeof(address) * num_public_addrs);

    ecall_get_public_addrs(global_eid, public_addrs);

    return public_addrs;
}


void ecall_test_func_w(void)
{

    ecall_test_func(global_eid);
}
