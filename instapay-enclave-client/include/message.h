#ifndef MESSAGE_H
#define MESSAGE_H

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

enum message_type {
	PAY     = 0,
    PAID    = 1,
    PM_REQ  = 2,
    AG_REQ  = 3,
    AG_RES  = 4,
    UD_REQ  = 5,
    UD_RES  = 6,
    CONFIRM = 7,
    CROSS_PREPARE_RES = 8,
    CROSS_COMMIT_RES = 9,
};

typedef struct participant {

    unsigned char party[41];
    unsigned int payment_size;
    unsigned int channel_ids[2];
    int payment_amount[2];

} Participant;

typedef struct message {
    /********* common *********/
    message_type type;

    /***** direct payment *****/
    unsigned int channel_id;
    int amount;
    unsigned int counter;

    /*** multi-hop payment ****/
    unsigned int payment_num;
    /*
    unsigned int payment_size;
    unsigned int channel_ids[2];
    int payment_amount[2];
    */
    Participant participant[3];
    unsigned int e;
} Message;

typedef struct message_res {
    /********* common *********/
    message_type type;

    int amount;
    unsigned int payment_num;
        unsigned int e;
} MessageRes;

void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature);
int verify_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr);
int verify_client_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr, unsigned int payment_num);

#endif
