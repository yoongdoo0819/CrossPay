#include "enclave.h"
#include "enclave_t.h"

#include <message.h>

secp256k1_context* secp256k1_ctx = NULL;
/*
void ecall_initializeSecp256k1CTX() {
	//secp256k1_ctx = NULL;
    	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	printf("SUCCESS \n");
}
*/
void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature)
{
    unsigned char *msg32;
    int recid;

    /* secp256k1 */
    //secp256k1_context* secp256k1_ctx = NULL;
    if(secp256k1_ctx == NULL) {
	    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    } 

//    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_ecdsa_recoverable_signature sig;

    unsigned char output64[64];

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    /* hashing the byte stream */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);
    /* ECDSA sign on the message */
//    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, msg32, seckey, NULL, NULL);

    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, output64, &recid, &sig);
    memcpy(signature, output64, 32);  // copy r
    memcpy(signature + 32, output64 + 32, 32);  // copy s
    memcpy(&signature[64], &recid, 1);  // copy v (recovery id)

//    printf("SIGN MSG \n");

//    secp256k1_context_destroy(secp256k1_ctx);
}


int verify_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr)
{
/*
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
*/
    if(secp256k1_ctx == NULL) {
	    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    } 

    secp256k1_ecdsa_recoverable_signature raw_sig;
    int v = signature[64];

//    printf("START 1 ################################## \n");
//    printf("v : %d \n", v);
    if(v > 3) v -= 27;
    if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v)) {
	//secp256k1_context_destroy(secp256k1_ctx);
	printf("sig parse compact fail! \n");
        return -1;
    }
//    printf("START 2 ################################## \n");

    unsigned char *msg32;
    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

//    printf("START 3 ################################## \n");

    secp256k1_pubkey raw_pubkey;
    if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32)) {
	printf("recover fail ! \n");
	//secp256k1_context_destroy(secp256k1_ctx);
        return -1;
    }

    unsigned char pubkey[65];
    size_t pubkey_len = 65;

//    printf("START 4 ################################## \n");

    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &pubkey_len, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

//    printf("START 5 ################################## \n");

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);

//    printf("START 6 ################################## \n");

    sha3_Update(&sha3_ctx, pubkey + 1, pubkey_len - 1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    unsigned char sender[20];
//    printf("START 7 ################################## \n");

    memcpy(sender, msg32 + 12, 20);
/*    
    printf("pubkey : ");
     for(int i = 0; i < 32; i++)
        printf("%02x", pubkey[i]);
    printf("\n");
   

    printf("IN verify_message (sender): ");
    for(int i = 0; i < 20; i++)
        printf("%02x", sender[i]);
    printf("\n");
*/
    
//    secp256k1_context_destroy(secp256k1_ctx);

//    printf("START 8 ################################## \n");

//    printf("VERIFY MSG \n");
    if(from == 0) {
        //pubaddr = ::arr_to_bytes(pubaddr, 40);
        if(memcmp(sender, pubaddr, 20) == 0) {

            return 0;
	}

        return 1;
    }
    else if(from == 1) {
        unsigned char *server_pubaddr = ::arr_to_bytes(SERVER_PUBADDR, 40);
        if(memcmp(sender, server_pubaddr, 20) == 0) {

	    delete server_pubaddr;
            return 0;
	}

	delete server_pubaddr;
        return 1;
    }

//    printf("START 9 ################################## \n");

}

int verify_client_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr, unsigned int payment_num)
{
/*
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
*/
    if(secp256k1_ctx == NULL) {
	    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    } 

    secp256k1_ecdsa_recoverable_signature raw_sig;
    int v = signature[64];

//    printf("START 1 ################################## \n");
//    printf("v : %d \n", v);
    if(v > 3) v -= 27;
    if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v)) {
	//secp256k1_context_destroy(secp256k1_ctx);
	printf("sig parse compact fail! \n");
        return -1;
    }
//    printf("START 2 ################################## \n");

    unsigned char *msg32;
    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

//    printf("START 3 ################################## \n");

    secp256k1_pubkey raw_pubkey;
    if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32)) {
	printf("recover fail ! \n");
	//secp256k1_context_destroy(secp256k1_ctx);
        return -1;
    }

    unsigned char pubkey[65];
    size_t pubkey_len = 65;

//    printf("START 4 ################################## \n");

    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &pubkey_len, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

//    printf("START 5 ################################## \n");

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);

//    printf("START 6 ################################## \n");

    sha3_Update(&sha3_ctx, pubkey + 1, pubkey_len - 1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    unsigned char sender[20];
//    printf("START 7 ################################## \n");

    memcpy(sender, msg32 + 12, 20);
/*    
    printf("pubkey : ");
     for(int i = 0; i < 32; i++)
        printf("%02x", pubkey[i]);
    printf("\n");
*/   
/*
    printf("IN verify_message (sender): ");
    for(int i = 0; i < 20; i++)
        printf("%02x", sender[i]);
    printf("\n");
*/
/*
    printf("IN verify_message (pubaddr): ");
    for(int i = 0; i < 20; i++)
	    printf("%02x", pubaddr[i]);
    printf("\n");                                                         
*/
    
//    secp256k1_context_destroy(secp256k1_ctx);

//    printf("START 8 ################################## \n");

//    printf("VERIFY MSG \n");
    if(from == 0) {
        pubaddr = ::arr_to_bytes(pubaddr, 40);
        if(memcmp(sender, pubaddr, 20) == 0) {

//	    printf("verification success \n");
	    free(pubaddr);
            return 0;
	}

	free(pubaddr);
        return 1;
    }
    else if(from == 1) {
        unsigned char *server_pubaddr = ::arr_to_bytes(SERVER_PUBADDR, 40);
        if(memcmp(sender, server_pubaddr, 20) == 0) {

	    delete server_pubaddr;
            return 0;
	}

	delete server_pubaddr;
        return 1;
    }

//    printf("START 9 ################################## \n");

}
