#ifndef CROSS_MESSAGE_H
#define CROSS_MESSAGE_H

#include <vector>
#include <util.h>

#define SERVER_PUBADDR  (unsigned char*)"7e58a6de07fa27d93716a77c369a1ab07f9d1682"

#if defined(__cplusplus)
extern "C" {
#endif

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <sha3.h>

#if defined(__cplusplus)
}
#endif

using namespace std;

enum cross_message_type {
    CROSS_PREPARE_REQ  = 1,
    CROSS_PREPARE_RES  = 2,
    CROSS_COMMIT_RES  = 3,
    CROSS_COMMIT_REQ  = 4,  
    CROSS_CONFIRM = 5,
};

typedef struct cross_message {
    /********* common *********/
    cross_message_type type;

    /***** direct payment *****/
    unsigned int channel_id;
    int amount;
    unsigned int counter;

    /*** multi-hop payment ****/
    unsigned int payment_num;
    unsigned int payment_size;
    unsigned int channel_ids[2];
    int payment_amount[2];
    unsigned int e;
} Cross_Message;

void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature);
int verify_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr);

#endif