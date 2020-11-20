#include <account.h>


using namespace std;


std::vector<unsigned char> Account::get_pubkey()
{
    /* secp256k1 */
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_pubkey pk;

    unsigned char *seckey = m_seckey.data();
    unsigned char output[65];

    size_t outputlen = 65;

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    unsigned char *msg32;

    /* get public key and serialize it */
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_ec_pubkey_create(secp256k1_ctx, &pk, seckey);
    secp256k1_ec_pubkey_serialize(secp256k1_ctx, output, &outputlen, &pk, SECP256K1_EC_UNCOMPRESSED);

    /* calculate public key hash */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, output + 1, outputlen-1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);
    //msg32 = reinterpret_cast<unsigned char*>(const_cast<void*>(sha3_Finalize(&sha3_ctx)));

    std::vector<unsigned char> pubkey(msg32 + 12, msg32 + 32);
    
    return pubkey;
}


std::vector<unsigned char> Account::get_seckey()
{    
    return m_seckey;
}


map_account accounts;
