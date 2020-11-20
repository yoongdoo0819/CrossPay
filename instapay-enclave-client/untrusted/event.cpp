#include "app.h"
#include "enclave_u.h"


void ecall_receive_create_channel_w(unsigned int channel_id, unsigned char *owner, unsigned char *receiver, unsigned int deposit)
{
    ecall_receive_create_channel(global_eid, channel_id, owner, receiver, deposit);
}


void ecall_receive_close_channel_w(unsigned int channel_id, unsigned int owner_bal, unsigned int receiver_bal)
{
    ecall_receive_close_channel(global_eid, channel_id, owner_bal, receiver_bal);
}