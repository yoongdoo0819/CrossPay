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
#include <cross_message.h>
#include <mutex>

//using namespace std;
std::mutex rwMutex;


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

/*    
    printf("[FROM SERVER] msg: ");
    for(int i = 0; i < 44; i++)
        printf("%02x", msg[i]);
    printf("\n");

    printf("[FROM SERVER] sig: ");
    for(int i = 0; i < 65; i++)
        printf("%02x", signature[i]);
    printf("\n");
*/    

    /* step 1. verify signature */
/*    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;
*/
    /* step 2. check that message type is 'AG_REQ' */
    verify_message(1, signature, msg, sizeof(Message), NULL);

    if(ag_req->type != AG_REQ)
        return;

    /* step 3. generate payment instance */

    payment_num = ag_req->payment_num;
    payment_size = ag_req->payment_size;
    channel_ids = ag_req->channel_ids;
    payment_amount = ag_req->payment_amount;

/*    
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");
*/    

//    rwMutex.lock();
    //payments.insert(map_payment_value(payment_num, Payment(payment_num)));

    for(int i = 0; i < payment_size; i++) {
        payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
        channels.find(channel_ids[i])->second.transition_to_pre_update();

        if(payment_amount[i] < 0)
            channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i] * -1;
    }

//    rwMutex.unlock();

    /* step 4. generate reply message */

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = AG_RES;
    reply.payment_num = payment_num;
    reply.e = 1;
    seckey = accounts.find(pubkey)->second.get_seckey();

//    printf("SIGN START \n");
    sign_message((unsigned char*)&reply, sizeof(Message), (unsigned char*)seckey.data(), reply_signature);
//    printf("SIGN END \n");

    memcpy(original_msg, (unsigned char*)&reply, sizeof(Message));
    memcpy(output, reply_signature, 65);

    //free(pubkey);
    //free(seckey);
    return;
}

void ecall_go_pre_update_two(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
    Message *ag_req = (Message*)msg;
    unsigned int payment_num = ag_req->payment_num;

    payments.insert(map_payment_value(payment_num, Payment(payment_num)));
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
/*
    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;
*/
    verify_message(1, signature, msg, sizeof(Message), NULL);

    /* step 2. check that message type is 'UD_REQ' */

    if(ud_req->type != UD_REQ)
        return;

    /* step 3. update channel state */

    payment_num = ud_req->payment_num;
    payment_size = ud_req->payment_size;
    channel_ids = ud_req->channel_ids;
    payment_amount = ud_req->payment_amount;

    /*
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");    
    */

    unsigned int value;
/*
    if(payments.find(payment_num) == payments.end()) {
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
        for(int i = 0; i < payment_size; i++)
            payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
    }
*/
    //rwMutex.lock();
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
    //rwMutex.unlock();

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

    //free(pubkey);
    //free(seckey);
    return;    
}

void ecall_go_post_update_two(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
    //rwMutex.unlock();

    /* step 4. generate reply message */
    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 
    Message reply;
    Message *ud_req = (Message*)msg;

    payment_num = ud_req->payment_num;
    payment_size = ud_req->payment_size;
    channel_ids = ud_req->channel_ids;
    payment_amount = ud_req->payment_amount;

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = UD_RES;
    reply.payment_num = payment_num;
    seckey = accounts.find(pubkey)->second.get_seckey();

    sign_message((unsigned char*)&reply, sizeof(Message), (unsigned char*)seckey.data(), reply_signature);

    memcpy(original_msg, (unsigned char*)&reply, sizeof(Message));
    memcpy(output, reply_signature, 65);

    //free(pubkey);
    //free(seckey);
    return;    
}

void ecall_go_idle(unsigned char *msg, unsigned char *signature)
{
    unsigned char reply_signature[65] = {0, };
    unsigned int payment_num;

    Message *confirm = (Message*)msg;

    /* step 1. verify signature */
/*
    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;
*/
    verify_message(1, signature, msg, sizeof(Message), NULL);

    /* step 2. check that message type is 'UD_REQ' */

    if(confirm->type != CONFIRM)
        return;

    /* step 3. complete payment */

    payment_num = confirm->payment_num;

    std::vector<Related> c = payments.find(payment_num)->second.m_related_channels;
    //rwMutex.lock();
    for(int i = 0; i < c.size(); i++)
        channels.find(c.at(i).channel_id)->second.transition_to_idle();
    //rwMutex.unlock();

    return;
}


void ecall_register_comminfo(unsigned int channel_id, unsigned char *ip, unsigned int ip_size, unsigned int port)
{
    channels.find(channel_id)->second.m_other_ip = ::copy_bytes(ip, ip_size);
    channels.find(channel_id)->second.m_other_port = port;
}


/*
 *
 *
 *
 * InstaPay 3.0
 */

void ecall_cross_go_pre_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Cross_Message *ag_req = (Cross_Message*)msg;
    Cross_Message reply;

    memset((unsigned char*)&reply, 0x00, sizeof(Cross_Message));

    printf("[FROM SERVER] msg: ");
/*    for(int i = 0; i < 44; i++)
        printf("%02x", msg[i]);
	*/
    printf("\n");

    printf("[FROM SERVER] sig: ");
/*    for(int i = 0; i < 65; i++)
        printf("%02x", signature[i]);
*/  printf("\n");

    /* step 1. verify signature */
    /*
    if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
        return;
*/

    /* step 2. check that message type is 'AG_REQ' */

    if(ag_req->type != CROSS_PREPARE_REQ)
    {
	printf("CROSS_PREPARE FAILURE \n");
        return;
    }

    printf("PREPARE MSG SUCCESS \n");

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
        channels.find(channel_ids[i])->second.transition_to_cross_pre_update();

        if(payment_amount[i] < 0) {
            channels.find(channel_ids[i])->second.m_reserved_balance += payment_amount[i] * -1;
            channels.find(channel_ids[i])->second.m_balance -= payment_amount[i] * -1;
	}


    	printf("channel %d pre_update reserved_bal : %d \n", i, channels.find(channel_ids[i])->second.m_reserved_balance);
    }

    /* step 4. generate reply message */

    printf("PREPARE START - GENERATE REPLY MESSAGE \n");
    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    printf("PREPARE START 1 - GENERATE REPLY MESSAGE \n");

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    printf("PREPARE START 2 - GENERATE REPLY MESSAGE \n");

    reply.type = CROSS_PREPARE_RES;
    reply.payment_num = payment_num;
    reply.e = 1;
    seckey = accounts.find(pubkey)->second.get_seckey();

    printf("PREPARE START 3 - GENERATE REPLY MESSAGE \n");

    sign_message((unsigned char*)&reply, sizeof(Cross_Message), (unsigned char*)seckey.data(), reply_signature);

    printf("PREPARE START 4 - GENERATE REPLY MESSAGE \n");

    memcpy(original_msg, (unsigned char*)&reply, sizeof(Cross_Message));

    printf("PREPARE START 5 - GENERATE REPLY MESSAGE \n");

    memcpy(output, reply_signature, 65);


    printf("PREPARE END - GENERATE REPLY MESSAGE \n");
    return;
}


void ecall_cross_go_post_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Cross_Message *ud_req = (Cross_Message*)msg;
    Cross_Message reply;

    memset((unsigned char*)&reply, 0x00, sizeof(Cross_Message));

    /* step 1. verify signature */
/*
    if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
        return;
*/
    /* step 2. check that message type is 'UD_REQ' */

    if(ud_req->type != CROSS_COMMIT_REQ)
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
	    channels.find(channel_ids[i])->second.m_reserved_balance += value;
            //channels.find(channel_ids[i])->second.paid(value);
        else {
            //channels.find(channel_ids[i])->second.m_reserved_balance += payment_amount[i];

            //channels.find(channel_ids[i])->second.pay(value);
        }

    	printf("channel %d post_update reserved_bal : %d \n", i, channels.find(channel_ids[i])->second.m_reserved_balance);

        channels.find(channel_ids[i])->second.transition_to_cross_post_update();
    }

    /* step 4. generate reply message */
    printf("COMMIT START - GENERATE REPLY MESSAGE \n");

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    printf("COMMIT START 1 - GENERATE REPLY MESSAGE \n");

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    printf("COMMIT START 2 - GENERATE REPLY MESSAGE \n");

    reply.type = CROSS_COMMIT_RES;
    reply.payment_num = payment_num;
    seckey = accounts.find(pubkey)->second.get_seckey();

    printf("COMMIT START 3 - GENERATE REPLY MESSAGE \n");

    sign_message((unsigned char*)&reply, sizeof(Cross_Message), (unsigned char*)seckey.data(), reply_signature);

    printf("COMMIT START 4 - GENERATE REPLY MESSAGE \n");

    memcpy(original_msg, (unsigned char*)&reply, sizeof(Cross_Message));

    printf("COMMIT START 5 - GENERATE REPLY MESSAGE \n");

    memcpy(output, reply_signature, 65);
    
    printf("COMMIT END - GENERATE REPLY MESSAGE \n");
    return;    
}


void ecall_cross_go_idle(unsigned char *msg, unsigned char *signature)
{
    unsigned char reply_signature[65] = {0, };

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 


    Cross_Message *confirm = (Cross_Message*)msg;

    /* step 1. verify signature */

    printf("cross_go_idle sig verification \n");
    /*
    if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
        return;
*/
    /* step 2. check that message type is 'UD_REQ' */

    printf("cross_go_idle type verification \n");
    if(confirm->type != CROSS_CONFIRM_REQ)
        return;

    /* step 3. complete payment */
/*
    payment_num = confirm->payment_num;

    std::vector<Related> c = payments.find(payment_num)->second.m_related_channels;
    for(int i = 0; i < c.size(); i++) {
        channels.find(c.at(i).channel_id)->second.transition_to_idle();

    }
*/

    payment_num = confirm->payment_num;
    payment_size = confirm->payment_size;
    channel_ids = confirm->channel_ids;
    payment_amount = confirm->payment_amount;

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

        if(0 < payment_amount[i]) {
	    channels.find(channel_ids[i])->second.m_reserved_balance -= value;
            channels.find(channel_ids[i])->second.m_balance += value;    
	//channels.find(channel_ids[i])->second.paid(value);
        }
        else {
	    channels.find(channel_ids[i])->second.m_reserved_balance -= value;
            //channels.find(channel_ids[i])->second.m_balance -= value;    

            //channels.find(channel_ids[i])->second.m_reserved_balance += payment_amount[i];
            //channels.find(channel_ids[i])->second.pay(value);
        }


	printf("=========== CORSS IDLE ============ \n");
        channels.find(channel_ids[i])->second.transition_to_idle();
    }

    printf("=========== CORSS IDLE END!!!! ============ \n");
    return;
}

void ecall_cross_refund(unsigned char *msg, unsigned char *signature)
{
    unsigned char reply_signature[65] = {0, };

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 


    Cross_Message *refund = (Cross_Message*)msg;

    /* step 1. verify signature */
/*
    printf("cross_refund sig verification \n");
    if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
        return;
*/
    /* step 2. check that message type is 'UD_REQ' */

    printf("cross_refund type verification \n");
    if(refund->type != CROSS_REFUND_REQ)
        return;

    printf("TYPE IS CROSS_REFUND_REQ \n");
    /* step 3. complete payment */
/*
    payment_num = confirm->payment_num;

    std::vector<Related> c = payments.find(payment_num)->second.m_related_channels;
    for(int i = 0; i < c.size(); i++) {
        channels.find(c.at(i).channel_id)->second.transition_to_idle();

    }
*/

    payment_num = refund->payment_num;
    payment_size = refund->payment_size;
    channel_ids = refund->channel_ids;
    payment_amount = refund->payment_amount;

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

	printf("Value : %d \n", value);

        if(0 < payment_amount[i]) {
	    printf("1 reserved_bal : %d \n", channels.find(channel_ids[i])->second.m_reserved_balance);
	    if(channels.find(channel_ids[i])->second.m_reserved_balance == value)           
		    channels.find(channel_ids[i])->second.m_reserved_balance -= value;
	    else
		    channels.find(channel_ids[i])->second.m_reserved_balance = 0;

        //    channels.find(channel_ids[i])->second.m_balance += value;    
	//channels.find(channel_ids[i])->second.paid(value);
        }
        else {
	    printf("2 reserved_bal : %d \n", channels.find(channel_ids[i])->second.m_reserved_balance);
	    printf("2 bal : %d \n", channels.find(channel_ids[i])->second.m_balance);
	    channels.find(channel_ids[i])->second.m_reserved_balance -= value;
            channels.find(channel_ids[i])->second.m_balance += value;    

            //channels.find(channel_ids[i])->second.m_reserved_balance += payment_amount[i];
            //channels.find(channel_ids[i])->second.pay(value);
        }

        channels.find(channel_ids[i])->second.transition_to_idle();
    }



    return;
}



