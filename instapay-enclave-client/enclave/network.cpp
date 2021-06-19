//#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include <stdint.h>
#include <cstring>
//#include <stdio.h>
#include <cstdio>

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

using namespace std;
std::mutex rwMutex;

void ecall_accept_payments(unsigned int payment_num)
{
    payments.insert(map_payment_value(payment_num, Payment(payment_num)));
}

void ecall_go_pre_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output, unsigned int *result)
{
//    printf("PRE UPDATE START \n");
    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Message *ag_req = (Message*)msg;
    MessageRes reply;

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
    /*
    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;
    */
    /* step 2. check that message type is 'AG_REQ' */
   
    verify_message(1, signature, msg, sizeof(Message), NULL);
    
//    printf("type : %d \n", ag_req->type);

    if(ag_req->type != AG_REQ) {
	printf("NOT AG REQ \n");
	printf("%d \n", ag_req->type);
	*result = 1;
        return;
    }

    /* step 3. generate payment instance */

    payment_num = ag_req->payment_num;
    /*
    payment_size = ag_req->payment_size;
    channel_ids = ag_req->channel_ids;
    payment_amount = ag_req->payment_amount;
    */
   
    unsigned char *pubAddr;
    unsigned int num_public_addrs;

    ecall_get_num_public_addrs(&num_public_addrs);
    pubAddr = (unsigned char*)malloc(sizeof(address) * num_public_addrs);

    ecall_get_public_addrs(pubAddr);

    unsigned char* strpubaddr[41] = {0, };

    int len;
    len = snprintf((char *)strpubaddr, 41, "%02x", pubAddr[0]);
    for(int i=1; i<20; i++) {
	    len += snprintf((char *)strpubaddr+len, 41, "%02x", pubAddr[i]);
//	    printf("str>>>> : %s \n", strpubaddr);
	    //if(!strcmp((char*)pubAddr[i], "f5"))
	//	    printf("OK \n");
//	    sprintf_s(strpubaddr, "%02x", pubAddr[i]);
//	    swprintf(strpubaddr, "%02x", (wchar_t)pubAddr[i]);
    }
    free(pubAddr);

/*    for(int i=0; i<40; i+=2) {
	    strpubaddr[i] = (unsigned char)pubAddr[i];
    }
*/
    
//    printf("str>>>> : %s \n", strpubaddr);

//    printf("%d \n", ag_req->payment_num);
//    printf("%d \n", ag_req->type); 

//    printf("%d \n", (ag_req->participant[0]).payment_size);
//    printf("%s \n", (ag_req->participant[0]).party);
//    printf("%d \n", (ag_req->participant[0]).payment_size);
//    printf("%d \n", (ag_req->participant[0]).channel_ids[0]);
/*
    printf("%s \n", ag_req->participant[1].party);
    printf("%d \n", ag_req->participant[1].payment_size);
    printf("%d \n", ag_req->participant[1].channel_ids[0]);
    printf("%d \n", ag_req->participant[1].channel_ids[1]);

    printf("%s \n", ag_req->participant[2].party);
    printf("%d \n", ag_req->participant[2].payment_size);
    printf("%d \n", ag_req->participant[2].channel_ids[0]);
    */
    unsigned char *tempMyAddr; 

    for(int i=0; i<3; i++) {
   	    tempMyAddr = ag_req->participant[i].party;
//	    printf("%d temp addr : %s \n", i+1, tempMyAddr);

	    if(!strcmp((char*)tempMyAddr, (char*)strpubaddr)) {
//		    printf("OK!! \n");

		    payment_size = ag_req->participant[i].payment_size;
		    channel_ids = ag_req->participant[i].channel_ids;
		    payment_amount = ag_req->participant[i].payment_amount;

		    break;
	    }	    
    }
/*    
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");
*/    


    for(int i = 0; i < payment_size; i++) {
        //ayments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
        channels.find(channel_ids[i])->second.transition_to_pre_update();

        if(payment_amount[i] < 0) {
            channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i] * -1;	
	    reply.amount = payment_amount[i] * -1; 
	} else {
		reply.amount = payment_amount[i];
	}

//	printf("%d channel is pre updated \n", channel_ids[i]);
    }


    /* step 4. generate reply message */

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = AG_RES;
    reply.payment_num = payment_num;
    reply.e = 1;
    seckey = accounts.find(pubkey)->second.get_seckey();

//    printf("SIGN START \n");
    sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);
//    printf("SIGN END \n");

    memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
    memcpy(output, reply_signature, 65);

//    printf("PRE UPDATED \n");
    *result = 9999;
    return;
}


void ecall_go_post_update(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char* crossServerSig, unsigned char *original_msg, unsigned char *output, unsigned int *result)
{
//    printf("POST UPDATE START \n");

    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Message *ud_req = (Message*)msg;
    MessageRes reply;

    memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

    /* step 1. verify signature */
/*
    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;
*/

    verify_message(1, senderSig, senderMSG, sizeof(MessageRes), NULL);
    verify_message(1, middleManSig, middleManMSG, sizeof(MessageRes), NULL);
    verify_message(1, receiverSig, receiverMSG, sizeof(MessageRes), NULL);

    MessageRes *senderMsg = (MessageRes*)senderMSG;
    MessageRes *middleManMsg = (MessageRes*)middleManMSG;
    MessageRes *receiverMsg = (MessageRes*)receiverMSG;
//    printf("%d %d %d \n", senderMsg->amount, middleManMsg->amount, receiverMsg->amount);

    if(senderMsg->amount == middleManMsg->amount && 
		    middleManMsg->amount == receiverMsg->amount) { /*printf("same amount !! \n");*/ }
    else { return; }

    verify_message(1, signature, msg, sizeof(Message), NULL);

    /* step 2. check that message type is 'UD_REQ' */

//    printf("type : %d \n", ud_req->type);

    if(ud_req->type != UD_REQ) {
	printf("NOT UD REQ \n");
	printf("%d \n", ud_req->type);
	*result = 1;
        return;
    }

    /* step 3. update channel state */

    payment_num = ud_req->payment_num;
    /*
    payment_size = ud_req->payment_size;
    channel_ids = ud_req->channel_ids;
    payment_amount = ud_req->payment_amount;
    */
 
    unsigned char *pubAddr;
    unsigned int num_public_addrs;

    ecall_get_num_public_addrs(&num_public_addrs);
    pubAddr = (unsigned char*)malloc(sizeof(address) * num_public_addrs);

    ecall_get_public_addrs(pubAddr);

    unsigned char* strpubaddr[41] = {0, };

    int len;
    len = snprintf((char *)strpubaddr, 41, "%02x", pubAddr[0]);
    for(int i=1; i<20; i++) {
	    len += snprintf((char *)strpubaddr+len, 41, "%02x", pubAddr[i]);
//	    printf("str>>>> : %s \n", strpubaddr);
	    //if(!strcmp((char*)pubAddr[i], "f5"))
	//	    printf("OK \n");
//	    sprintf_s(strpubaddr, "%02x", pubAddr[i]);
//	    swprintf(strpubaddr, "%02x", (wchar_t)pubAddr[i]);
    }
    free(pubAddr);

/*    for(int i=0; i<40; i+=2) {
	    strpubaddr[i] = (unsigned char)pubAddr[i];
    }
*/
    /*
    printf("str>>>> : %s \n", strpubaddr);

    printf("%d \n", ud_req->payment_num);
    printf("%d \n", ud_req->type); 

    printf("%s \n", (ud_req->participant[0]).party);
    printf("%d \n", (ud_req->participant[0]).payment_size);
    printf("%d \n", (ud_req->participant[0]).channel_ids[0]);

    printf("%s \n", ud_req->participant[1].party);
    printf("%d \n", ud_req->participant[1].payment_size);
    printf("%d \n", ud_req->participant[1].channel_ids[0]);
    printf("%d \n", ud_req->participant[1].channel_ids[1]);

    printf("%s \n", ud_req->participant[2].party);
    printf("%d \n", ud_req->participant[2].payment_size);
    printf("%d \n", ud_req->participant[2].channel_ids[0]);
    */
    unsigned char *tempMyAddr; 

    for(int i=0; i<3; i++) {
   	    tempMyAddr = ud_req->participant[i].party;
//	    printf("%d temp addr : %s \n", i+1, tempMyAddr);

	    if(!strcmp((char*)tempMyAddr, (char*)strpubaddr)) {
//		    printf("OK!! \n");

		    payment_size = ud_req->participant[i].payment_size;
		    channel_ids = ud_req->participant[i].channel_ids;
		    payment_amount = ud_req->participant[i].payment_amount;

		    break;
	    }	    
    }

//    printf("pn : %d POST UPDATE START \n", payment_num);
//    printf("ps : %d \n", payment_size);
/*   
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");    
*/    

//    printf("#################################### \n");
    unsigned int value;
/*
    if(payments.find(payment_num) == payments.end()) {
	printf("payment.insert \n");
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
        for(int i = 0; i < payment_size; i++)
            payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
    }
*/
    //rwMutex.lock();
    
    for(int i = 0; i < payment_size; i++) {
//	printf("payment size : %d POST UPDATE PAYMENT SIZE \n", payment_size);

        value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];

        if(0 < payment_amount[i]) {
            channels.find(channel_ids[i])->second.paid(value);
	    reply.amount = value;
//	    printf("reply.amount %d \n", value);
	}
        else {
            channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i];
            channels.find(channel_ids[i])->second.pay(value);

	    reply.amount = value;
//	    printf("reply.amount %d \n", value);
        }

        channels.find(channel_ids[i])->second.transition_to_post_update();
//	printf("channel %d is post updated \n", channel_ids[i]);
    }

    //rwMutex.unlock();

    /* step 4. generate reply message */

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = UD_RES;
    reply.payment_num = payment_num;
    reply.e = 1;

    seckey = accounts.find(pubkey)->second.get_seckey();
    sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);

    memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
    memcpy(output, reply_signature, 65);

    //free(pubkey);
    //free(seckey);
//    printf("%d POST UPDATED \n", payment_num);
    *result = 9999;
    return;    
}

void ecall_go_idle(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char *crossServerSig, unsigned int *result)
{
//    printf("IDLE UPDATE START \n");

    unsigned char reply_signature[65] = {0, };

    unsigned char *my_addr;
    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;

    Message *confirm = (Message*)msg;

    /* step 1. verify signature */
/*
    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;
*/

    verify_message(1, senderSig, senderMSG, sizeof(MessageRes), NULL);
    verify_message(1, middleManSig, middleManMSG, sizeof(MessageRes), NULL);
    verify_message(1, receiverSig, receiverMSG, sizeof(MessageRes), NULL);

    Message *senderMsg = (Message*)senderMSG;
    Message *middleManMsg = (Message*)middleManMSG;
    Message *receiverMsg = (Message*)receiverMSG;

    if(senderMsg->amount == middleManMsg->amount && 
		    middleManMsg->amount == receiverMsg->amount) { /*printf("same amount !! \n");*/ }
    else { return; }

    verify_message(1, signature, msg, sizeof(Message), NULL);

    /* step 2. check that message type is 'UD_REQ' */

    if(confirm->type != CONFIRM) {
	printf("NOT CONFIRM REQ \n");
	printf("%d \n", confirm->type);
	*result = 1;
        return;
    }

    payment_num = confirm->payment_num;
    /*
    payment_size = ud_req->payment_size;
    channel_ids = ud_req->channel_ids;
    payment_amount = ud_req->payment_amount;
    */
 
    unsigned char *pubAddr;
    unsigned int num_public_addrs;

    ecall_get_num_public_addrs(&num_public_addrs);
    pubAddr = (unsigned char*)malloc(sizeof(address) * num_public_addrs);

    ecall_get_public_addrs(pubAddr);

    unsigned char* strpubaddr[41] = {0, };

    int len;
    len = snprintf((char *)strpubaddr, 41, "%02x", pubAddr[0]);
    for(int i=1; i<20; i++) {
	    len += snprintf((char *)strpubaddr+len, 41, "%02x", pubAddr[i]);
//	    printf("str>>>> : %s \n", strpubaddr);
	    //if(!strcmp((char*)pubAddr[i], "f5"))
	//	    printf("OK \n");
//	    sprintf_s(strpubaddr, "%02x", pubAddr[i]);
//	    swprintf(strpubaddr, "%02x", (wchar_t)pubAddr[i]);
    }
    free(pubAddr);

/*    for(int i=0; i<40; i+=2) {
	    strpubaddr[i] = (unsigned char)pubAddr[i];
    }
*/

    /*    
    printf("str>>>> : %s \n", strpubaddr);

    printf("%d \n", confirm->payment_num);
    printf("%d \n", confirm->type); 

    printf("%s \n", (confirm->participant[0]).party);
    printf("%d \n", (confirm->participant[0]).payment_size);
    printf("%d \n", (confirm->participant[0]).channel_ids[0]);

    printf("%s \n", confirm->participant[1].party);
    printf("%d \n", confirm->participant[1].payment_size);
    printf("%d \n", confirm->participant[1].channel_ids[0]);
    printf("%d \n", confirm->participant[1].channel_ids[1]);

    printf("%s \n", confirm->participant[2].party);
    printf("%d \n", confirm->participant[2].payment_size);
    printf("%d \n", confirm->participant[2].channel_ids[0]);
    */

    unsigned char *tempMyAddr; 

    for(int i=0; i<3; i++) {
   	    tempMyAddr = confirm->participant[i].party;
//	    printf("%d temp addr : %s \n", i+1, tempMyAddr);

	    if(!strcmp((char*)tempMyAddr, (char*)strpubaddr)) {
//		    printf("OK!! \n");

		    payment_size = confirm->participant[i].payment_size;
		    channel_ids = confirm->participant[i].channel_ids;		    
		    //payment_amount = confirm->participant[i].payment_amount;
		    break;
	    }	    
    }

//    printf("pn : %d POST UPDATE START \n", payment_num);
//    printf("ps : %d \n", payment_size);
/*   
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");    
*/    

/*
    if(payments.find(payment_num) == payments.end()) {
	printf("payment.insert \n");
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
        for(int i = 0; i < payment_size; i++)
            payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
    }
*/
    //rwMutex.lock();
    
    for(int i = 0; i < payment_size; i++) {
//	printf("payment size : %d POST UPDATE PAYMENT SIZE \n", payment_size);
/*
        value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];

        if(0 < payment_amount[i])
            channels.find(channel_ids[i])->second.paid(value);
        else {
            channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i];
            channels.find(channel_ids[i])->second.pay(value);
        }
*/
        channels.find(channel_ids[i])->second.transition_to_idle();
//	printf("channel %d is idle updated \n", channel_ids[i]);
    }

    *result = 9999;
    return;

    /* step 3. complete payment */
/*
    payment_num = confirm->payment_num;

    std::vector<Related> c = payments.find(payment_num)->second.m_related_channels;
    //rwMutex.lock();
    for(int i = 0; i < c.size(); i++) {
        channels.find(c.at(i).channel_id)->second.transition_to_idle();
	printf("%d channel is idle updated \n", c.at(i).channel_id);
    }
    //rwMutex.unlock();

    printf("IDLE UPDATED \n");
    *result = 9999;
    return;
*/

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

void ecall_cross_go_pre_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output, unsigned int *result)
{
    //printf("PRE UPDATE START \n");
    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Cross_Message *prepare_req = (Cross_Message*)msg;
    MessageRes reply;

    memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

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
    
    if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL)) {
	printf("verification failure ! \n");
        return;
    }

    /* step 2. check that message type is 'AG_REQ' */
   
//    verify_message(1, signature, msg, sizeof(Cross_Message), NULL);
    
//    printf("type : %d \n", ag_req->type);

    if(prepare_req->type != CROSS_PREPARE_REQ) {
	printf("NOT CROSS_PREPARE_REQ \n");
	printf("%d \n", prepare_req->type);
	*result = 1;
        return;
    }

    /* step 3. generate payment instance */

    payment_num = prepare_req->payment_num;
    /*
    payment_size = ag_req->payment_size;
    channel_ids = ag_req->channel_ids;
    payment_amount = ag_req->payment_amount;
    */
   
    unsigned char *pubAddr;
    unsigned int num_public_addrs;

    ecall_get_num_public_addrs(&num_public_addrs);
    pubAddr = (unsigned char*)malloc(sizeof(address) * num_public_addrs);

    ecall_get_public_addrs(pubAddr);

    unsigned char* strpubaddr[41] = {0, };

    int len;
    len = snprintf((char *)strpubaddr, 41, "%02x", pubAddr[0]);
    for(int i=1; i<20; i++) {
	    len += snprintf((char *)strpubaddr+len, 41, "%02x", pubAddr[i]);
//	    printf("str>>>> : %s \n", strpubaddr);
	    //if(!strcmp((char*)pubAddr[i], "f5"))
	//	    printf("OK \n");
//	    sprintf_s(strpubaddr, "%02x", pubAddr[i]);
//	    swprintf(strpubaddr, "%02x", (wchar_t)pubAddr[i]);
    }
    free(pubAddr);

/*    for(int i=0; i<40; i+=2) {
	    strpubaddr[i] = (unsigned char)pubAddr[i];
    }
*/
    
//    printf("str>>>> : %s \n", strpubaddr);

//    printf("%d \n", ag_req->payment_num);
//    printf("%d \n", ag_req->type); 

//    printf("%d \n", (ag_req->participant[0]).payment_size);
//    printf("%s \n", (ag_req->participant[0]).party);
//    printf("%d \n", (ag_req->participant[0]).payment_size);
//    printf("%d \n", (ag_req->participant[0]).channel_ids[0]);
/*
    printf("%s \n", ag_req->participant[1].party);
    printf("%d \n", ag_req->participant[1].payment_size);
    printf("%d \n", ag_req->participant[1].channel_ids[0]);
    printf("%d \n", ag_req->participant[1].channel_ids[1]);

    printf("%s \n", ag_req->participant[2].party);
    printf("%d \n", ag_req->participant[2].payment_size);
    printf("%d \n", ag_req->participant[2].channel_ids[0]);
    */
    unsigned char *tempMyAddr; 

    for(int i=0; i<3; i++) {
   	    tempMyAddr = prepare_req->participant[i].party;
//	    printf("%d temp addr : %s \n", i+1, tempMyAddr);

	    if(!strcmp((char*)tempMyAddr, (char*)strpubaddr)) {
//		    printf("OK!! \n");

		    payment_size = prepare_req->participant[i].payment_size;
		    channel_ids = prepare_req->participant[i].channel_ids;
		    payment_amount = prepare_req->participant[i].payment_amount;

		    break;
	    }	    
    }
/*    
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");
*/    

//    rwMutex.lock();
    //payments.insert(map_payment_value(payment_num, Payment(payment_num)));
    
    for(int i = 0; i < payment_size; i++) {
        //ayments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
        //channels.find(channel_ids[i])->second.transition_to_pre_update();
        channels.find(channel_ids[i])->second.transition_to_cross_pre_update();

        if(payment_amount[i] < 0) {
            channels.find(channel_ids[i])->second.m_reserved_balance += payment_amount[i] * -1;
            //channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i] * -1;	
	    channels.find(channel_ids[i])->second.m_balance -= payment_amount[i] * -1;

	    reply.amount = payment_amount[i] * -1; 
	} else {
		reply.amount = payment_amount[i];
	}

	//printf("%d channel is pre updated \n", channel_ids[i]);
    }

//    rwMutex.unlock();

    /* step 4. generate reply message */

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = CROSS_PREPARE_RES;
    reply.payment_num = payment_num;
    reply.e = 1;
    seckey = accounts.find(pubkey)->second.get_seckey();

//    printf("SIGN START \n");
    sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);
//    printf("SIGN END \n");

    memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
    memcpy(output, reply_signature, 65);

    //free(pubkey);
    //free(seckey);

//    printf("PRE UPDATED \n");
    *result = 9999;
    return;
}

void ecall_cross_go_post_update(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char* crossServerSig, unsigned char *original_msg, unsigned char *output, unsigned int *result)
{
 //    printf("POST UPDATE START \n");

    unsigned char reply_signature[65] = {0, };
    unsigned char *my_addr;

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Cross_Message *ud_req = (Cross_Message*)msg;
    MessageRes reply;

    memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

    /* step 1. verify signature */

    if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
        return;


    verify_message(1, senderSig, senderMSG, sizeof(MessageRes), NULL);
    verify_message(1, middleManSig, middleManMSG, sizeof(MessageRes), NULL);
    verify_message(1, receiverSig, receiverMSG, sizeof(MessageRes), NULL);

    MessageRes *senderMsg = (MessageRes*)senderMSG;
    MessageRes *middleManMsg = (MessageRes*)middleManMSG;
    MessageRes *receiverMsg = (MessageRes*)receiverMSG;
//    printf("%d %d %d \n", senderMsg->amount, middleManMsg->amount, receiverMsg->amount);

    if(senderMsg->amount == middleManMsg->amount && 
		    middleManMsg->amount == receiverMsg->amount) { /*printf("same amount !! \n");*/ }
    else { return; }

//    verify_message(1, signature, msg, sizeof(Cross_Message), NULL);

    /* step 2. check that message type is 'UD_REQ' */

//    printf("type : %d \n", ud_req->type);

    if(ud_req->type != CROSS_COMMIT_REQ) {
	printf("NOT UD REQ \n");
	printf("%d \n", ud_req->type);
	*result = 1;
        return;
    }

    /* step 3. update channel state */

    payment_num = ud_req->payment_num;
    /*
    payment_size = ud_req->payment_size;
    channel_ids = ud_req->channel_ids;
    payment_amount = ud_req->payment_amount;
    */
 
    unsigned char *pubAddr;
    unsigned int num_public_addrs;

    ecall_get_num_public_addrs(&num_public_addrs);
    pubAddr = (unsigned char*)malloc(sizeof(address) * num_public_addrs);

    ecall_get_public_addrs(pubAddr);

    unsigned char* strpubaddr[41] = {0, };

    int len;
    len = snprintf((char *)strpubaddr, 41, "%02x", pubAddr[0]);
    for(int i=1; i<20; i++) {
	    len += snprintf((char *)strpubaddr+len, 41, "%02x", pubAddr[i]);
//	    printf("str>>>> : %s \n", strpubaddr);
	    //if(!strcmp((char*)pubAddr[i], "f5"))
	//	    printf("OK \n");
//	    sprintf_s(strpubaddr, "%02x", pubAddr[i]);
//	    swprintf(strpubaddr, "%02x", (wchar_t)pubAddr[i]);
    }
    free(pubAddr);

/*    for(int i=0; i<40; i+=2) {
	    strpubaddr[i] = (unsigned char)pubAddr[i];
    }
*/
    /*
    printf("str>>>> : %s \n", strpubaddr);

    printf("%d \n", ud_req->payment_num);
    printf("%d \n", ud_req->type); 

    printf("%s \n", (ud_req->participant[0]).party);
    printf("%d \n", (ud_req->participant[0]).payment_size);
    printf("%d \n", (ud_req->participant[0]).channel_ids[0]);

    printf("%s \n", ud_req->participant[1].party);
    printf("%d \n", ud_req->participant[1].payment_size);
    printf("%d \n", ud_req->participant[1].channel_ids[0]);
    printf("%d \n", ud_req->participant[1].channel_ids[1]);

    printf("%s \n", ud_req->participant[2].party);
    printf("%d \n", ud_req->participant[2].payment_size);
    printf("%d \n", ud_req->participant[2].channel_ids[0]);
    */
    unsigned char *tempMyAddr; 

    for(int i=0; i<3; i++) {
   	    tempMyAddr = ud_req->participant[i].party;
//	    printf("%d temp addr : %s \n", i+1, tempMyAddr);

	    if(!strcmp((char*)tempMyAddr, (char*)strpubaddr)) {
//		    printf("OK!! \n");

		    payment_size = ud_req->participant[i].payment_size;
		    channel_ids = ud_req->participant[i].channel_ids;
		    payment_amount = ud_req->participant[i].payment_amount;

		    break;
	    }	    
    }

//    printf("pn : %d POST UPDATE START \n", payment_num);
//    printf("ps : %d \n", payment_size);
/*   
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");    
*/    

//    printf("#################################### \n");
    unsigned int value;
/*
    if(payments.find(payment_num) == payments.end()) {
	printf("payment.insert \n");
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
        for(int i = 0; i < payment_size; i++)
            payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
    }
*/
    //rwMutex.lock();
    
    for(int i = 0; i < payment_size; i++) {
//	printf("payment size : %d POST UPDATE PAYMENT SIZE \n", payment_size);

        value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];
 
        if(0 < payment_amount[i]) {
 	    channels.find(channel_ids[i])->second.m_reserved_balance += value;
  	    //channels.find(channel_ids[i])->second.paid(value);
	    reply.amount = value;
//	    printf("reply.amount %d \n", value);
	}
        else {
            //channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i];
            //channels.find(channel_ids[i])->second.pay(value);

	    reply.amount = value;
//	    printf("reply.amount %d \n", value);
        }

        channels.find(channel_ids[i])->second.transition_to_cross_post_update();
//	printf("channel %d is post updated \n", channel_ids[i]);
    }

    //rwMutex.unlock();

    /* step 4. generate reply message */

    my_addr = channels.find(channel_ids[0])->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    reply.type = CROSS_COMMIT_RES;
    reply.payment_num = payment_num;
    reply.e = 1;

    seckey = accounts.find(pubkey)->second.get_seckey();
    sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);

    memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
    memcpy(output, reply_signature, 65);

    //free(pubkey);
    //free(seckey);
//    printf("%d POST UPDATED \n", payment_num);
    *result = 9999;
    return;    
}

void ecall_cross_go_idle(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *crossServerMSG, unsigned char *crossServerSig, unsigned int *result)
{
//    printf("IDLE UPDATE START \n");

    unsigned char reply_signature[65] = {0, };

    unsigned char *my_addr;
    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 

    Cross_Message *confirm = (Cross_Message*)msg;

    /* step 1. verify signature */

    if(verify_message(1, signature, msg, sizeof(Message), NULL))
        return;


    verify_message(1, senderSig, senderMSG, sizeof(MessageRes), NULL);
    verify_message(1, middleManSig, middleManMSG, sizeof(MessageRes), NULL);
    verify_message(1, receiverSig, receiverMSG, sizeof(MessageRes), NULL);

    Message *senderMsg = (Message*)senderMSG;
    Message *middleManMsg = (Message*)middleManMSG;
    Message *receiverMsg = (Message*)receiverMSG;


    if(senderMsg->amount == middleManMsg->amount && 
		    middleManMsg->amount == receiverMsg->amount) { /*printf("same amount !! \n");*/ }
    else { return; }

//    verify_message(1, signature, msg, sizeof(Cross_Message), NULL);

    /* step 2. check that message type is 'UD_REQ' */

    if(confirm->type != CROSS_CONFIRM_REQ) {
	printf("NOT CROSS CONFIRM REQ \n");
	printf("%d \n", confirm->type);
	*result = 1;
        return;
    }

    payment_num = confirm->payment_num;
    /*
    payment_size = ud_req->payment_size;
    channel_ids = ud_req->channel_ids;
    payment_amount = ud_req->payment_amount;
    */
 
    unsigned char *pubAddr;
    unsigned int num_public_addrs;

    ecall_get_num_public_addrs(&num_public_addrs);
    pubAddr = (unsigned char*)malloc(sizeof(address) * num_public_addrs);

    ecall_get_public_addrs(pubAddr);

    unsigned char* strpubaddr[41] = {0, };

    int len;
    len = snprintf((char *)strpubaddr, 41, "%02x", pubAddr[0]);
    for(int i=1; i<20; i++) {
	    len += snprintf((char *)strpubaddr+len, 41, "%02x", pubAddr[i]);
//	    printf("str>>>> : %s \n", strpubaddr);
	    //if(!strcmp((char*)pubAddr[i], "f5"))
	//	    printf("OK \n");
//	    sprintf_s(strpubaddr, "%02x", pubAddr[i]);
//	    swprintf(strpubaddr, "%02x", (wchar_t)pubAddr[i]);
    }
    free(pubAddr);

/*    for(int i=0; i<40; i+=2) {
	    strpubaddr[i] = (unsigned char)pubAddr[i];
    }
*/

    /*    
    printf("str>>>> : %s \n", strpubaddr);

    printf("%d \n", confirm->payment_num);
    printf("%d \n", confirm->type); 

    printf("%s \n", (confirm->participant[0]).party);
    printf("%d \n", (confirm->participant[0]).payment_size);
    printf("%d \n", (confirm->participant[0]).channel_ids[0]);

    printf("%s \n", confirm->participant[1].party);
    printf("%d \n", confirm->participant[1].payment_size);
    printf("%d \n", confirm->participant[1].channel_ids[0]);
    printf("%d \n", confirm->participant[1].channel_ids[1]);

    printf("%s \n", confirm->participant[2].party);
    printf("%d \n", confirm->participant[2].payment_size);
    printf("%d \n", confirm->participant[2].channel_ids[0]);
    */

    unsigned char *tempMyAddr; 

    for(int i=0; i<3; i++) {
   	    tempMyAddr = confirm->participant[i].party;
//	    printf("%d temp addr : %s \n", i+1, tempMyAddr);

	    if(!strcmp((char*)tempMyAddr, (char*)strpubaddr)) {
//		    printf("OK!! \n");

		    payment_size = confirm->participant[i].payment_size;
		    channel_ids = confirm->participant[i].channel_ids;		    
		    payment_amount = confirm->participant[i].payment_amount;
		    break;
	    }	    
    }

//    printf("pn : %d POST UPDATE START \n", payment_num);
//    printf("ps : %d \n", payment_size);
/*   
    printf("channel ids: ");
    for(int i = 0; i < payment_size; i++)
        printf("[%d] ", channel_ids[i]);
    printf("\n");    
*/    

/*
    if(payments.find(payment_num) == payments.end()) {
	printf("payment.insert \n");
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
        for(int i = 0; i < payment_size; i++)
            payments.find(payment_num)->second.add_element(channel_ids[i], payment_amount[i]);
    }
*/
    //rwMutex.lock();
    
    for(int i = 0; i < payment_size; i++) {
//	printf("payment size : %d POST UPDATE PAYMENT SIZE \n", payment_size);
/*
        value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];

        if(0 < payment_amount[i])
            channels.find(channel_ids[i])->second.paid(value);
        else {
            channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i];
            channels.find(channel_ids[i])->second.pay(value);
        }
*/
	unsigned int value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];

	if(0 < payment_amount[i]) {
		channels.find(channel_ids[i])->second.m_reserved_balance -= value;
		channels.find(channel_ids[i])->second.m_balance += value;
		//channels.find(channel_ids[i])->second.paid(value);
        }
	else {
		channels.find(channel_ids[i])->second.m_reserved_balance -= value;
	}

        channels.find(channel_ids[i])->second.transition_to_cross_idle();
//	printf("channel %d is idle updated \n", channel_ids[i]);
    }

    *result = 9999;
    return;
    return;
}

void ecall_cross_refund(unsigned char *msg, unsigned char *signature)
{
/*    unsigned char reply_signature[65] = {0, };

    unsigned int payment_num, payment_size;
    unsigned int *channel_ids;
    int *payment_amount; 


    Cross_Message *refund = (Cross_Message*)msg;
*/
    /* step 1. verify signature */
/*
    printf("cross_refund sig verification \n");
    if(verify_message(1, signature, msg, sizeof(Cross_Message), NULL))
        return;
*/
    /* step 2. check that message type is 'UD_REQ' */
/*
    printf("cross_refund type verification \n");
    if(refund->type != CROSS_REFUND_REQ)
        return;

    printf("TYPE IS CROSS_REFUND_REQ \n");
*/
    /* step 3. complete payment */
/*
    payment_num = confirm->payment_num;

    std::vector<Related> c = payments.find(payment_num)->second.m_related_channels;
    for(int i = 0; i < c.size(); i++) {
        channels.find(c.at(i).channel_id)->second.transition_to_idle();

    }
*/
/*
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


*/
    return;
}



