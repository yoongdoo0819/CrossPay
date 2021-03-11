#include "app.h"
#include "enclave_u.h"

#include <string.h>


void ecall_go_pre_update_w(unsigned char *msg, unsigned char *signature, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message)];
    unsigned char *reply_sig = new unsigned char[65];

    memset(reply_msg, 0x00, sizeof(message));
    memset(reply_sig, 0x00, 65);

    ecall_go_pre_update(global_eid, msg, signature, reply_msg, reply_sig);

    *original_msg = reply_msg;
    *output = reply_sig;
}


void ecall_go_post_update_w(unsigned char *msg, unsigned char *signature, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message)];
    unsigned char *reply_sig = new unsigned char[65];

    memset(reply_msg, 0x00, sizeof(message));
    memset(reply_sig, 0x00, 65);

    ecall_go_post_update(global_eid, msg, signature, reply_msg, reply_sig);

    *original_msg = reply_msg;
    *output = reply_sig;
}


void ecall_go_idle_w(unsigned char *msg, unsigned char *signature)
{
    ecall_go_idle(global_eid, msg, signature);    
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

void ecall_cross_go_pre_update_w(unsigned char *msg, unsigned char *signature, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message)];
    unsigned char *reply_sig = new unsigned char[65];

    memset(reply_msg, 0x00, sizeof(message));
    memset(reply_sig, 0x00, 65);

    ecall_cross_go_pre_update(global_eid, msg, signature, reply_msg, reply_sig);

    *original_msg = reply_msg;
    *output = reply_sig;
}


void ecall_cross_go_post_update_w(unsigned char *msg, unsigned char *signature, unsigned char **original_msg, unsigned char **output)
{
    unsigned char *reply_msg = new unsigned char[sizeof(message)];
    unsigned char *reply_sig = new unsigned char[65];

    memset(reply_msg, 0x00, sizeof(message));
    memset(reply_sig, 0x00, 65);

    ecall_cross_go_post_update(global_eid, msg, signature, reply_msg, reply_sig);

    *original_msg = reply_msg;
    *output = reply_sig;
}


void ecall_cross_go_idle_w(unsigned char *msg, unsigned char *signature)
{
    ecall_cross_go_idle(global_eid, msg, signature);    
}

void ecall_cross_refund_w(unsigned char *msg, unsigned char *signature)
{
    ecall_cross_refund(global_eid, msg, signature);    
}

