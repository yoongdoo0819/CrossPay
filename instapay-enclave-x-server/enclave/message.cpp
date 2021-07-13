#include "enclave.h"
#include "enclave_t.h"

#include "sgx_tcrypto.h"
#include <message.h>
#include <cross_payment.h>

secp256k1_context* secp256k1_ctx = NULL;

void ecall_initSecp256k1CTX() {
	for(int i=0; i<1; i++) {
		secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	}
}

void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature, unsigned int payment_num)
{
/*
 *
 * RSA signature
 *
	unsigned char p_n[256];
	unsigned char p_d[256];
	unsigned char p_p[256];
	unsigned char p_q[256];
	unsigned char p_dmp1[256];
	unsigned char p_dmq1[256];
	unsigned char p_iqmp[256];

	int n_byte_size = 256;
	long e = 65537;


	printf("Dd \n");
	sgx_status_t ret_create_key_params = sgx_create_rsa_key_pair(n_byte_size, sizeof(e), p_n, p_d, (unsigned char*)&e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp);

	if (ret_create_key_params != SGX_SUCCESS) {
//		    ocall_print("Key param generation failed");
//			ocall_print(std::to_string(ret_create_key_params).c_str());
		printf("fail ! \n");
	} else {
//		    ocall_print((char *) p_q);
	}

	void *private_key = NULL;

	sgx_status_t ret_create_private_key = sgx_create_rsa_priv2_key(n_byte_size, sizeof(e), (unsigned char*)&e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &private_key);

	if ( ret_create_private_key != SGX_SUCCESS) {
//		    ocall_print("Private key generation failed");
//			ocall_print(std::to_string(ret_create_private_key).c_str());
		printf("fail ! \n");			
	}

	printf("%s \n", private_key);
	void *public_key = NULL;

	sgx_status_t ret_create_public_key = sgx_create_rsa_pub1_key(n_byte_size, sizeof(e), p_n, (unsigned char*)&e, &public_key);

	if ( ret_create_public_key != SGX_SUCCESS) {
//		    ocall_print("Public key generation failed");
//			ocall_print(std::to_string(ret_create_public_key).c_str());
		printf("fail ! \n");			
	}

	char * pin_data = "Hello World!";
	size_t out_len = 0;

	sgx_status_t ret_get_output_len = sgx_rsa_pub_encrypt_sha256(public_key, NULL, &out_len, (unsigned char *)pin_data, strlen(pin_data));

	if ( ret_get_output_len != SGX_SUCCESS) {
//		    ocall_print("Determination of output length failed");
//			ocall_print(std::to_string(ret_get_output_len).c_str());
		printf("fail ! \n");
	}

	unsigned char pout_data[out_len];

	sgx_status_t ret_encrypt = sgx_rsa_pub_encrypt_sha256(public_key, pout_data, &out_len, (unsigned char *)pin_data, strlen(pin_data));

	if ( ret_encrypt != SGX_SUCCESS) {
//		    ocall_print("Encryption failed");
//			ocall_print(std::to_string(ret_encrypt).c_str());
		printf("ss \n");
	} else {
//		    ocall_print(std::to_string(out_len).c_str());
	}

	size_t decrypted_out_len = 0;

	sgx_status_t ret_determine_decrypt_len = sgx_rsa_priv_decrypt_sha256(private_key, NULL, &decrypted_out_len, pout_data, sizeof(pout_data));

	if ( ret_determine_decrypt_len != SGX_SUCCESS) {
//		    ocall_print("Determination of decrypted output length failed");
//			ocall_print(std::to_string(ret_determine_decrypt_len).c_str());
		printf("ff \n");
	}

	printf("%d \n", decrypted_out_len);
	unsigned char decrypted_pout_data[decrypted_out_len];
        
	sgx_status_t ret_decrypt = sgx_rsa_priv_decrypt_sha256(private_key, decrypted_pout_data, &decrypted_out_len, pout_data, sizeof(pout_data));

	if ( ret_decrypt != SGX_SUCCESS) {
//		    ocall_print("Decryption failed");
//			ocall_print(std::to_string(ret_decrypt).c_str());
		printf("cc \n");
	} else {
		printf("Decrypted MESSAGE: %s \n", decrypted_pout_data);
//			ocall_print((char *) decrypted_pout_data);
//			    ocall_print(std::to_string(decrypted_out_len).c_str());
	}
*/

    unsigned char *msg32;
    int recid;


    /* secp256k1 */
    //secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ecdsa_recoverable_signature sig;
/*    if(secp256k1_ctx[payment_num%10] == NULL) {
	    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
*/
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
    unsigned char *msg32;

/*
 *
 * ecdsa_verify
 *
 
    unsigned char *msg32;// = (unsigned char*)abc;

    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubKey;
//    unsigned char pubk[65] = "042c93312fad479d5f1bcea4be26fb3eae7024185d9da0cb540b0bf85a46a7c5";
//    size_t pubKeyLen = 65;

//    secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx, &sig, signature);

//    int ret = secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubKey, pubk, pubKeyLen);
//    printf("%d \n", ret);

    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

//    secp256k1_ecdsa_verify(secp256k1_ctx, &sig, msg32, &pubKey);
//    return 0;

*/

    secp256k1_ecdsa_recoverable_signature raw_sig;
    int v = signature[64];

    if(v > 3) v -= 27;

    if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v))
        return -1;

    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

/*
    for(int i=0; i<16; i++) {
	    printf("%02x", msg32[i]);
    }
    printf("\n");
*/
    secp256k1_pubkey raw_pubkey;
    if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32))
        return -1;

    unsigned char pubkey[65];
    size_t pubkey_len = 65;

    secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &pubkey_len, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

/*    
    for(int i=0; i<32; i++) {
	    printf("%02x", pubkey[i]);
    }
    printf("\n");
*/
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
	
//    secp256k1_context_destroy(secp256k1_ctx);


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
       // unsigned char *server_pubaddr = ::arr_to_bytes(SERVER_PUBADDR, 40);

/*	
	printf("server_pubaddr :");
	for(int i=0; i<20; i++)
		printf("%02x", cross_payments.find(payment_num)->second.m_chain2Receiver[i]);
	printf("\n");
*/
/*
	if (memcmp((const char*)sender, (const char *)cross_payments.find(payment_num)->second.m_chain1Sender, 20) == 0) {
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
	    /*
	if (strcmp((const char*)sender, (const char *)cross_payments.find(payment_num)->second.m_chain1Sender)) {
		cross_payments.find(payment_num)->second.m_chain1Sender_prepared = 1;
	}
	else if (strcmp((const char*)sender, (const char*)cross_payments.find(payment_num)->second.m_chain1MiddleMan)) {
		cross_payments.find(payment_num)->second.m_chain1MiddleMan_prepared = 1;
	}
	else if (strcmp((const char*)sender, (const char*)cross_payments.find(payment_num)->second.m_chain1Receiver)) {
		cross_payments.find(payment_num)->second.m_chain1Receiver_prepared = 1;
	}
	else if (strcmp((const char*)sender, (const char*)cross_payments.find(payment_num)->second.m_chain2Sender)) {
		cross_payments.find(payment_num)->second.m_chain2Sender_prepared = 1;
	}
	else if (strcmp((const char*)sender, (const char*)cross_payments.find(payment_num)->second.m_chain2MiddleMan)) {
		cross_payments.find(payment_num)->second.m_chain2MiddleMan_prepared = 1;
	}
	else if (strcmp((const char*)sender, (const char*)cross_payments.find(payment_num)->second.m_chain2Receiver)) {
		cross_payments.find(payment_num)->second.m_chain2Receiver_prepared = 1;
	}
*/
//	printf("VERIFY PREPARE MSG ! \n");
/*        if(memcmp(sender, server_pubaddr, 20) == 0) {
	    free(server_pubaddr);
            return 0;
	}

	free(server_pubaddr);
        return 1;
*/
    }

}


int verify_committed_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr, unsigned int payment_num)
{
 
    secp256k1_ecdsa_recoverable_signature raw_sig;
    int v = signature[64];

    if(v > 3) v -= 27;

    if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v))
        return -1;

    unsigned char *msg32;
    sha3_context sha3_ctx;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);


    secp256k1_pubkey raw_pubkey;
    if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32))
        return -1;

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
	
//    secp256k1_context_destroy(secp256k1_ctx);


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
	
//	printf("VERIFY COMMIT MSG ! \n");

        if(memcmp(sender, server_pubaddr, 20) == 0) {
	    free(server_pubaddr);
            return 0;
	}

	free(server_pubaddr);
        return 1;
    }
}
