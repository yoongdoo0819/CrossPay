#include "enclave.h"
#include "enclave_t.h"

#include <message.h>
#include <cross_payment.h>

secp256k1_context* secp256k1_ctx = NULL;


void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature)
{
    unsigned char *msg32;
    int recid;

    /* secp256k1 */
    //secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ecdsa_recoverable_signature sig;
    if(secp256k1_ctx == NULL) {
	    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    unsigned char output64[64];

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    /* hashing the byte stream */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);
/*
    for(int i=0; i<16; i++) {
	    printf("%02x \n", msg32[i]);
    }
*/
    /* ECDSA sign on the message */
//    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, msg32, seckey, NULL, NULL);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, output64, &recid, &sig);

    memcpy(signature, output64, 32);  // copy r
    memcpy(signature + 32, output64 + 32, 32);  // copy s
    memcpy(&signature[64], &recid, 1);  // copy v (recovery id)
/*
    for(int i = 0; i < 32; i++)
        printf("%02x", output64[i]);
    printf("\n");
*/
//    secp256k1_context_destroy(secp256k1_ctx);
}


int verify_prepared_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr, unsigned int payment_num)
{

    if(secp256k1_ctx == NULL) {	
	    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }


    //secp256k1_context* secp256k1_ctx = NULL;
//    secp256k1_ctx = secp256k1_context_create(/*SECP256K1_CONTEXT_SIGN |*/ SECP256K1_CONTEXT_VERIFY);
 
    secp256k1_ecdsa_recoverable_signature raw_sig;
    int v = signature[64];

    if(v > 3) v -= 27;

    //secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v))
        return -1;

    unsigned char *msg32;
    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

//    printf("START 2 !!!!! \n");

    secp256k1_pubkey raw_pubkey;
    if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32))
        return -1;

    unsigned char pubkey[65];
    size_t pubkey_len = 65;

    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &pubkey_len, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

//    printf("START 3 !!!!! \n");

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, pubkey + 1, pubkey_len - 1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    unsigned char sender[20];

//    printf("START 4 !!!!! \n");

   
    memcpy(sender, msg32 + 12, 20);
    
/*
    printf("IN verify_message (sender): ");
    for(int i = 0; i < 20; i++)
        printf("%02x", sender[i]);
    printf("\n");
*/    
	
//    secp256k1_context_destroy(secp256k1_ctx);

//    printf("START 5 !!!!! \n");

    if(from == 0) {
        pubaddr = ::arr_to_bytes(pubaddr, 40);
        if(memcmp(sender, pubaddr, 20) == 0) {
		free(pubaddr);
		return 0;
	}
	free(pubaddr);
        return 1;
    }
    else if(from == 1) {
        unsigned char *server_pubaddr = ::arr_to_bytes(SERVER_PUBADDR, 40);
/*	
	printf("server_pubaddr :");
	for(int i=0; i<20; i++)
		printf("%02x", cross_payments.find(payment_num)->second.m_chain2Receiver[i]);
	printf("\n");
*/
/*
	if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain1Sender, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain1Sender_prepared = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain1MiddleMan, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain1MiddleMan_prepared = 1;

	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain1Receiver, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain1Receiver_prepared = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain2Sender, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain2Sender_prepared = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain2MiddleMan, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain2MiddleMan_prepared = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain2Receiver, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain2Receiver_prepared = 1;
	}
*/	
	//    	printf("START 6 !!!!! \n");

        if(memcmp(sender, server_pubaddr, 20) == 0) {
	    free(server_pubaddr);
            return 0;
	}

	free(server_pubaddr);
        return 1;
    }
}


int verify_committed_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr, unsigned int payment_num)
{

    if(secp256k1_ctx == NULL) {	
	    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }


    //secp256k1_context* secp256k1_ctx = NULL;
//    secp256k1_ctx = secp256k1_context_create(/*SECP256K1_CONTEXT_SIGN |*/ SECP256K1_CONTEXT_VERIFY);
 
    secp256k1_ecdsa_recoverable_signature raw_sig;
    int v = signature[64];

    if(v > 3) v -= 27;

    //secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v))
        return -1;

    unsigned char *msg32;
    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

//    printf("START 2 !!!!! \n");

    secp256k1_pubkey raw_pubkey;
    if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32))
        return -1;

    unsigned char pubkey[65];
    size_t pubkey_len = 65;

    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &pubkey_len, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

//    printf("START 3 !!!!! \n");

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, pubkey + 1, pubkey_len - 1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    unsigned char sender[20];

//    printf("START 4 !!!!! \n");

   
    memcpy(sender, msg32 + 12, 20);
    
/*
    printf("IN verify_message (sender): ");
    for(int i = 0; i < 20; i++)
        printf("%02x", sender[i]);
    printf("\n");
*/    
	
//    secp256k1_context_destroy(secp256k1_ctx);

//    printf("START 5 !!!!! \n");

    if(from == 0) {
        pubaddr = ::arr_to_bytes(pubaddr, 40);
        if(memcmp(sender, pubaddr, 20) == 0) {
		free(pubaddr);
		return 0;
	}
	free(pubaddr);
        return 1;
    }
    else if(from == 1) {
        unsigned char *server_pubaddr = ::arr_to_bytes(SERVER_PUBADDR, 40);
/*	
	printf("server_pubaddr :");
	for(int i=0; i<20; i++)
		printf("%02x", cross_payments.find(payment_num)->second.m_chain2Receiver[i]);
	printf("\n");
*/
/*
	if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain1Sender, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain1Sender_committed = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain1MiddleMan, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain1MiddleMan_committed = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain1Receiver, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain1Receiver_committed = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain2Sender, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain2Sender_committed = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain2MiddleMan, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain2MiddleMan_committed = 1;
	}
	else if (memcmp(sender, cross_payments.find(payment_num)->second.m_chain2Receiver, 20) == 0) {
		cross_payments.find(payment_num)->second.m_chain2Receiver_committed = 1;
	}
*/	
	//    	printf("START 6 !!!!! \n");

        if(memcmp(sender, server_pubaddr, 20) == 0) {
	    free(server_pubaddr);
            return 0;
	}

	free(server_pubaddr);
        return 1;
    }
}
