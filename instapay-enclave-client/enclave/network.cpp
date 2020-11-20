#include <string.h>
#include <stdint.h>
#include <cstring>

#include "sgx_trts.h"
#include "enclave.h"
#include "enclave_t.h"

#include <account.h>
#include <channel.h>
#include <transaction.h>
#include <payment.h>
#include <message.h>
#include <util.h>


using namespace std;


void ecall_go_pre_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Message *ag_req = (Message*)msg;
    Message reply;

    memset((unsigned char*)&reply, 0x00, sizeof(Message));

    printf("[FROM SERVER] msg: ");
    for(int i = 0; i < 44; i++)
        printf("%02x", msg[i]);
    printf("\n");

    printf("[FROM SERVER] sig: ");
    for(int i = 0; i < 65; i++)
        printf("%02x", signature[i]);
    printf("\n");

    /* step 1. verify signature */
    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;

    /* step 2. check that message type is 'AG_REQ' */

    if(ag_req->type != AG_REQ)
        return;

    /* step 3. generate payment instance */

    payment_num = ag_req->payment_num;
    payment_size = ag_req->payment_size;
    channel_ids = ag_req->channel_ids;
    payment_amount = ag_req->payment_amount;

    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");

    payments.insert(map_payment_value(payment_num, Payment(payment_num)));

    for(int i = 0; i < payment_size; i++) {
        payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
        channels.find(channel_ids[i])->second.transition_to_pre_update();

        if(payment_amount[i] < 0)
            channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i] * -1;
    }

    /* step 4. generate reply message */

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = AG_RES;
    reply.payment_num = payment_num;
    reply.e = 1;
    seckey = accounts.find(pubkey)->second.get_seckey();

    sign_message((unsigned char*)&reply, sizeof(Message), (unsigned char*)seckey.data(), reply_signature);

    memcpy(original_msg, (unsigned char*)&reply, sizeof(Message));
    memcpy(output, reply_signature, 65);

    return;
}


void ecall_go_post_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Message *ud_req = (Message*)msg;
    Message reply;

    memset((unsigned char*)&reply, 0x00, sizeof(Message));

    /* step 1. verify signature */

    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;

    /* step 2. check that message type is 'UD_REQ' */

    if(ud_req->type != UD_REQ)
        return;

    /* step 3. update channel state */

    payment_num = ud_req->payment_num;
    payment_size = ud_req->payment_size;
    channel_ids = ud_req->channel_ids;
    payment_amount = ud_req->payment_amount;

    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");    

    unsigned int value;

    if(payments.find(payment_num) == payments.end()) {
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
        for(int i = 0; i < payment_size; i++)
            payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
    }

    for(int i = 0; i < payment_size; i++) {
        value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];

        if(0 < payment_amount[i])
            channels.find(channel_ids[i])->second.paid(value);
        else {
            channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i];
            channels.find(channel_ids[i])->second.pay(value);
        }

        channels.find(channel_ids[i])->second.transition_to_post_update();
    }

    /* step 4. generate reply message */

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = UD_RES;
    reply.payment_num = payment_num;
    seckey = accounts.find(pubkey)->second.get_seckey();

    sign_message((unsigned char*)&reply, sizeof(Message), (unsigned char*)seckey.data(), reply_signature);

    memcpy(original_msg, (unsigned char*)&reply, sizeof(Message));
    memcpy(output, reply_signature, 65);

    return;    
}


void ecall_go_idle(unsigned char *msg, unsigned char *signature)
{
    unsigned char reply_signature[65] = {0, };
    unsigned int payment_num;

    Message *confirm = (Message*)msg;

    /* step 1. verify signature */

    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;

    /* step 2. check that message type is 'UD_REQ' */

    if(confirm->type != CONFIRM)
        return;

    /* step 3. complete payment */

    payment_num = confirm->payment_num;

    std::vector<Related> c = payments.find(payment_num)->second.m_related_channels;
    for(int i = 0; i < c.size(); i++)
        channels.find(c.at(i).channel_id)->second.transition_to_idle();

    return;
}


void ecall_register_comminfo(unsigned int channel_id, unsigned char *ip, unsigned int ip_size, unsigned int port)
{
    channels.find(channel_id)->second.m_other_ip = ::copy_bytes(ip, ip_size);
    channels.find(channel_id)->second.m_other_port = port;
}