#include <stdio.h>
#include <cstring>
#include <algorithm>

#include "sgx_trts.h"
#include "enclave.h"
#include "enclave_t.h"
#include <transaction.h>


using namespace std;


std::vector<unsigned char> Transaction::encode(bool is_signed)
{
    std::vector<unsigned char> output;

    RLPValue encoded;
    std::vector<RLPValue> rlp_tx(9);

    std::string temp;

    rlp_tx.at(0).assign(::int_to_bytes(m_nonce));
    rlp_tx.at(1).assign(::int_to_bytes(m_gas_price));
    rlp_tx.at(2).assign(::int_to_bytes(m_gas_limit));
    rlp_tx.at(3).assign(std::vector<unsigned char>(m_to, m_to + 20));
    rlp_tx.at(4).assign(::int_to_bytes(m_value));
    rlp_tx.at(5).assign(std::vector<unsigned char>(m_data, m_data + m_data_size));
    rlp_tx.at(6).assign(::int_to_bytes(m_v));

    if(is_signed == false) {
        rlp_tx.at(7).assign("");
        rlp_tx.at(8).assign("");
    }
    else {
        rlp_tx.at(7).assign(std::vector<unsigned char>(m_r, m_r + 32));
        rlp_tx.at(8).assign(std::vector<unsigned char>(m_s, m_s + 32));
    }

    encoded.setArray();
    encoded.push_backV(rlp_tx);

    temp = encoded.write();
    output = std::vector<unsigned char>(temp.begin(), temp.end());

    return output;
}


void Transaction::sign(unsigned char *seckey_arr)
{
    std::vector<unsigned char> encoded;

    encoded = encode(false);

    unsigned char *tx_stream = reinterpret_cast<unsigned char*>(encoded.data());
    unsigned int stream_size = encoded.size();
    unsigned char *msg32;

    /* secp256k1 */
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ecdsa_signature sig;

    //unsigned char *seckey = ::arr_to_bytes(seckey_arr, 64);
    unsigned char output64[64];

    printf("[TX.cpp] Sec Key : ");
    for(int i=0; i<32; i++)
	    printf("%02x", seckey_arr[i]);
    printf("\n");

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    /* hashing the byte stream */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, tx_stream, stream_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    /* ECDSA sign on the message */
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_sign(secp256k1_ctx, &sig, msg32, seckey_arr, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, output64, &sig);

    printf("output : ");
    for(int i=0; i<64; i++)
	printf("%02x", output64[i]);
    printf("\n");

    m_v = (m_v * 2) + 35;         // 잘 안되면 35로 바꿔볼 것. 그리고 잘 안되면 또 다시 36으로 변경
    memcpy(m_r, output64, 32);
    memcpy(m_s, output64 + 32, 32);

    signed_tx = encode(true);
}
