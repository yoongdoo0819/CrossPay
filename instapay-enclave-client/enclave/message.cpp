#include "enclave.h"
#include "enclave_t.h"

#include <message.h>


void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature)
{
    unsigned char *msg32;
    int recid;

//    printf("start\n");
    /* secp256k1 */
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ecdsa_recoverable_signature sig;

    unsigned char output64[64];

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    /* hashing the byte stream */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);
//    printf("start2 \n");
    /* ECDSA sign on the message */
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
//    printf("start2 - 1 \n");

    secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, msg32, seckey, NULL, NULL);
//    printf("start2 - 2 \n");

    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, output64, &recid, &sig);
//    printf("start3 \n");
    memcpy(signature, output64, 32);  // copy r
    memcpy(signature + 32, output64 + 32, 32);  // copy s
    memcpy(&signature[64], &recid, 1);  // copy v (recovery id)
//    printf("start4 \n");

    secp256k1_context_destroy(secp256k1_ctx);
}


int verify_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr)
{
	
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_ecdsa_recoverable_signature raw_sig;
    int v = signature[64];

    if(v > 3) v -= 27;
    if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v)) {
	secp256k1_context_destroy(secp256k1_ctx);
        return -1;
    }

    unsigned char *msg32;
    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    secp256k1_pubkey raw_pubkey;
    if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32)) {
	secp256k1_context_destroy(secp256k1_ctx);
        return -1;
    }

//    free(msg32);
    unsigned char pubkey[65];
    size_t pubkey_len = 65;

    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &pubkey_len, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, pubkey + 1, pubkey_len - 1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    unsigned char sender[20];
    
    memcpy(sender, msg32 + 12, 20);
    
/*
    printf("IN verify_message (sender): ");
    for(int i = 0; i < 20; i++)
        printf("%02x", sender[i]);
    printf("\n");
*/
    
    secp256k1_context_destroy(secp256k1_ctx);

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
    
}
