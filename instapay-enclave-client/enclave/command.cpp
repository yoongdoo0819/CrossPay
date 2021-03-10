#include <stdio.h>    // vsnprintf
#include <stdarg.h>   // va_list
#include <string.h>
#include <stdint.h>
#include <cstring>
#include <typeinfo>

#include "sgx_trts.h"
#include "enclave.h"
#include "enclave_t.h"

#include <account.h>
#include <channel.h>
#include <payment.h>
#include <transaction.h>
#include <message.h>
#include <util.h>


using namespace std;


/* this function is only for debugging. it must be removed in the product */
void ecall_preset_account(unsigned char *addr, unsigned char *seckey)
{
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    unsigned char *seckey_bytes = ::arr_to_bytes(seckey, 64);

    std::vector<unsigned char> p(addr_bytes, addr_bytes + 20);
    std::vector<unsigned char> s(seckey_bytes, seckey_bytes + 32);
    accounts.insert(map_account_value(p, Account(s)));

    return;
}


void ecall_preset_payment(unsigned int pn, unsigned int channel_id, int amount)
{
    payments.insert(map_payment_value(pn, Payment(pn)));
    payments.find(pn)->second.add_element(channel_id, amount);

    return;
}


void ecall_create_account(unsigned char *generated_addr)
{
    /* generate a secret key */
    unsigned char *seckey = new unsigned char[32];
    sgx_read_rand(seckey, 32);

    /* secp256k1 */
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_pubkey pk;

    secp256k1_ecdsa_signature sig;

    unsigned char *msg32;
    unsigned char output[65];

    size_t outputlen = 65;

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    /* get public key and serialize it */
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_ec_pubkey_create(secp256k1_ctx, &pk, seckey);
    secp256k1_ec_pubkey_serialize(secp256k1_ctx, output, &outputlen, &pk, SECP256K1_EC_UNCOMPRESSED);

    /* calculate public key hash */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, output + 1, outputlen-1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    std::vector<unsigned char> p(msg32 + 12, msg32 + 32);
    std::vector<unsigned char> s(seckey, seckey + 32);
    accounts.insert(map_account_value(p, Account(s)));

    copy(msg32 + 12, msg32 + 32, generated_addr);

    printf("generated addr : ");
    for(int i=0; i<20; i++) {
	   printf("%02x", generated_addr[i]);
    }
    printf("\n");
    printf("secret key : ");
    for(int i=0; i<32; i++) {
	    printf("%02x", s[i]);
    }
    printf("\n");
    return;
}


void ecall_create_channel(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int deposit, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    std::vector<unsigned char> data;

    printf("ecall create channel start >> owner : %s \n", (unsigned char*)owner);
    for(int i=0; i<32; i++) 
	    printf("%02x", owner[i]);
    printf("\n");
    printf("ecall create channel start >> receiver : %s \n", (unsigned char*)receiver);
    for(int i=0; i<32; i++)
	    printf("%02x", receiver[i]);
    printf("\n");

    /* encode ABI for calling "create_channel(address)" on the contract */
    sha3_context sha3_ctx;
    unsigned char *func = (unsigned char*)"create_channel(address)";
    unsigned char *msg32;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, func, strlen((char*)func));
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    unsigned char *addr = ::arr_to_bytes(receiver, 40);
    data.insert(data.end(), msg32, msg32 + 4);
    
    for(int i = 0; i < 12; i++){
	    data.insert(data.end(), 0);
    }

    data.insert(data.end(), addr, addr + 20);

    // deposit *= 1000000000000000000;

    /* generate a transaction creating a channel */
    //Transaction tx(nonce, CONTRACT_ADDR, deposit, data.data(), data.size());
    printf("Contract Addr : %s \n", CONTRACT_ADDR);
    // find the account's private key and sign on transaction using
    addr = ::arr_to_bytes(owner, 40);
    std::vector<unsigned char> pubkey(addr, addr + 20);
    std::vector<unsigned char> seckey;
    std::vector<unsigned char> pubkey2;

    Transaction tx(nonce, CONTRACT_ADDR, deposit, data.data(), data.size());

    printf("========== create channel ========= \n");
  
    printf("addr : ");
    for(int i=0; i<32; i++) {
	    printf("%02x", addr[i]);
    }printf("\n"); 
    printf("owner : %s \n", (unsigned char*)owner);
    printf("receiver : %s \n", (unsigned char*)receiver);
    seckey = accounts.find(pubkey)->second.get_seckey();
    pubkey2 = accounts.find(pubkey)->second.get_pubkey();
    printf("seckey.data() : %s \n", (unsigned char*)seckey.data());
    for(int i=0; i<seckey.size(); i++)
	    printf("%02x", seckey.at(i));
    tx.sign((unsigned char*)seckey.data());  // "e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd"
    //printf("seckey : %s \n", (unsigned char*)seckey);
    //printf("seckey.data : %s \n", (unsigned char*)seckey.data());
    printf("pubkey : ");
    
    for(int i=0; i<20; i++) {
	    printf("%02x", pubkey[i]);
    }printf("\n");
    //for(int i=0; i<sizeof(pubkey)/sizeof(pubkey[0]); i++)
    //	    printf("%02x", pubkey[i]);
    printf("len : %d \n", pubkey.size());

    printf("pubkey2 : ");
    for(int i=0; i<20; i++) {
	printf("%02x", pubkey2[i]);
    }printf("\n");
    printf("len : %d \n", pubkey2.size());
//    printf(" >> %s \n", typeid(pubkey).name());
//    printf(" >> %s \n", typeid(pubkey2).name());
    printf("seckey : ");
    for(int i=0; i<32; i++) {
	    printf("%02x", seckey[i]);
    }
    printf("\n");
    printf("len : %d \n", seckey.size());
/*
    printf("seckey.data : ");
    for(int i=0; i<32; i++)
	    printf("%02x", seckey.data()[i]);
*/
    //printf("signed_tx : %s \n", (unsigned char*)signed_tx);
    //printf("tx.signed_tx.data() : %s \n", (unsigned char*)tx.signed_tx.data());

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();
/*
    printf("nonce : %s \n", (unsigned char*) nonce);
    printf("contract addr : %s \n", CONTRACT_ADDR);
    printf("deposit : %d \n", deposit);
    printf("signed tx : %s \n", signed_tx);
    for(int i=0; i<tx.signed_tx.size(); i++)
	    printf("%02x", signed_tx[i]);
*/
    printf("############### end #####################  \n");
    //fflush(stdout);
    return;
}

void ecall_onchain_payment(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int amount, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    Transaction tx(nonce, receiver, amount, NULL, 0);

    // find the account's private key and sign on transaction using
    unsigned char *addr = ::arr_to_bytes(owner, 40);
    std::vector<unsigned char> pubkey(addr, addr + 20);
    std::vector<unsigned char> seckey;

    seckey = accounts.find(pubkey)->second.get_seckey();
    tx.sign((unsigned char*)seckey.data());

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    return;
}


void ecall_pay(unsigned int channel_id, unsigned int amount, int *is_success, unsigned char *original_msg, unsigned char *output)
{
    unsigned char signature[65] = {0, };
    unsigned char *my_addr = channels.find(channel_id)->second.m_my_addr;

    int rand_num;

    Message msg;
    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    memset((unsigned char*)&msg, 0x00, sizeof(Message));

    if(channels.find(channel_id) == channels.end()) {
        *is_success = false;
        return;
    }

    if(channels.find(channel_id)->second.m_balance < amount) {
        *is_success = false;
        return;
    }

    if(channels.find(channel_id)->second.m_balance - channels.find(channel_id)->second.m_locked_balance < amount) {
        *is_success = false;
        return;
    }

    // if(channels.find(channel_id)->second.m_counter == 0) {
    //     sgx_read_rand((unsigned char*)&rand_num, 4);
    //     channels.find(channel_id)->second.m_counter = rand_num;
    // }

    *is_success = true;
    msg.type = PAY;
    msg.channel_id = channel_id;
    msg.amount = amount;
    msg.counter = channels.find(channel_id)->second.m_counter;
    seckey = accounts.find(pubkey)->second.get_seckey();

    sign_message((unsigned char*)&msg, sizeof(Message), (unsigned char*)seckey.data(), signature);

    memcpy(original_msg, (unsigned char*)&msg, sizeof(Message));
    memcpy(output, signature, 65);

    return;
}


void ecall_paid(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
    Message *direct_payment = (Message*)msg;
    Message reply;

    unsigned char reply_signature[65] = {0, };
    unsigned char *other_addr = channels.find(direct_payment->channel_id)->second.m_other_addr;
    unsigned char *my_addr = channels.find(direct_payment->channel_id)->second.m_my_addr;

    std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
    std::vector<unsigned char> seckey;

    memset((unsigned char*)&reply, 0x00, sizeof(Message));

    /* step 1. verify signature */

    if(verify_message(0, signature, msg, sizeof(Message), other_addr)) {    // other_addr
        printf("ERROR: fail to verify message\n");
        return;
    }

    /* step 2. check that message type is 'PAY' */

    if(direct_payment->type != PAY) {
        printf("ERROR: type is not \'PAY\'\n");
        return;
    }

    if(channels.find(direct_payment->channel_id) == channels.end()) {
        printf("ERROR: there is no channel %d\n", direct_payment->channel_id);
        return;
    }

    /* step 3. verify the counter */

    // if(channels.find(direct_payment->channel_id)->second.m_counter == 0) {
    //     channels.find(direct_payment->channel_id)->second.m_counter = direct_payment->counter;
    // }
    // else if(channels.find(direct_payment->channel_id)->second.m_counter + 1 == direct_payment->counter){
    //     (channels.find(direct_payment->channel_id)->second.m_counter)++;
    // }
    // else {
    //     printf("ERROR: counter is invalid\n");
    //     return;
    // }

    /* step 4. apply balance change */

    channels.find(direct_payment->channel_id)->second.paid(direct_payment->amount);

    /* step 5. generate reply message */

    reply.type = PAID;
    reply.channel_id = direct_payment->channel_id;
    reply.amount = direct_payment->amount;
    seckey = accounts.find(pubkey)->second.get_seckey();

    sign_message((unsigned char*)&reply, sizeof(Message), (unsigned char*)seckey.data(), reply_signature);

    memcpy(original_msg, (unsigned char*)&reply, sizeof(Message));
    memcpy(output, reply_signature, 65);

    return;
}


void ecall_pay_accepted(unsigned char *msg, unsigned char *signature)
{
    Message *reply_msg = (Message*)msg;
    unsigned char *my_addr = channels.find(reply_msg->channel_id)->second.m_my_addr;
    unsigned char *other_addr = channels.find(reply_msg->channel_id)->second.m_other_addr;

    // printf("========= IN ecall_pay_accepted ========\n");
    // printf("other addr: ");
    // for(int i = 0; i < 20; i++)
    //     printf("%02x", other_addr[i]);
    // printf("\n");
    // printf("========================================\n");

    /* step 1. verify signature */

    if(verify_message(0, signature, msg, sizeof(Message), other_addr))
        return;

    /* step 2. check that message type is 'PAID' */

    if(reply_msg->type != PAID)
        return;

    channels.find(reply_msg->channel_id)->second.pay(reply_msg->amount);
}


void ecall_get_balance(unsigned int channel_id, unsigned int *balance)
{
    *balance = channels.find(channel_id)->second.get_balance();
    return;
}


void ecall_get_channel_info(unsigned int channel_id, unsigned char *channel_info)
{
    channel ch_struct;
    Channel ch;

    if(channels.find(channel_id) == channels.end())
        return;

    ch = channels.find(channel_id)->second;

    ch_struct.m_id = ch.m_id;
    ch_struct.m_is_in = ch.m_is_in;
    ch_struct.m_status = ch.m_status;
    memcpy(ch_struct.m_my_addr, ch.m_my_addr, 20);
    ch_struct.m_my_deposit = ch.m_my_deposit;
    ch_struct.m_other_deposit = ch.m_other_deposit;
    ch_struct.m_balance = ch.m_balance;
    ch_struct.m_locked_balance = ch.m_locked_balance;
    memcpy(ch_struct.m_other_addr, ch.m_other_addr, 20);
    
    // cross-payment
    ch_struct.m_reserved_balance = ch.m_reserved_balance;

    memcpy((void*)channel_info, (void*)&ch_struct, sizeof(channel));
}


void ecall_close_channel(unsigned int nonce, unsigned char *owner, unsigned int channel_id, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    std::vector<unsigned char> data;

    printf("===== CLOSE CHANNEL START IN ENCLAVE ===== \n");
    /*** reject in cross-payment ***/
    unsigned int stage = channels.find(channel_id)->second.m_status;
    if(stage == C_PRE || stage == C_POST) {
	    printf("===== IMPOSSIBLE IN C_PRE or C_POST ===== \n");
	    return;
    }


    /* encode ABI for calling "close_channel(uint256,uint256,uint256)" on the contract */
    sha3_context sha3_ctx;
    unsigned char *func = (unsigned char*)"close_channel(uint256,uint256,uint256)";
    unsigned char *msg32;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, func, strlen((char*)func));
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);


    /* get owner(source) and receiver's(target) balances */
    unsigned int source_bal, target_bal;

    if(channels.find(channel_id)->second.m_is_in == 0) { // owner is me
        source_bal = channels.find(channel_id)->second.m_balance;
        target_bal = channels.find(channel_id)->second.m_my_deposit - channels.find(channel_id)->second.m_balance;
    }
    else {  // owner is not me
        source_bal = channels.find(channel_id)->second.m_other_deposit - channels.find(channel_id)->second.m_balance;
        target_bal = channels.find(channel_id)->second.m_balance;
    }

    data.insert(data.end(), msg32, msg32 + 4);


    /* convert to numbers which have leading zeros to use as contract function's arguments */
    unsigned char *channel_id_bytes, *source_bal_bytes, *target_bal_bytes;

    channel_id_bytes = create_uint256_argument(channel_id);
    source_bal_bytes = create_uint256_argument(source_bal);
    target_bal_bytes = create_uint256_argument(target_bal);
    
    data.insert(data.end(), channel_id_bytes, channel_id_bytes + 32);
    data.insert(data.end(), source_bal_bytes, source_bal_bytes + 32);
    data.insert(data.end(), target_bal_bytes, target_bal_bytes + 32);

    printf("===== CLOSE CHANNEL TX IS GENERATED IN ENCLAVE ===== \n");
    /* generate a transaction creating a channel */
    Transaction tx(nonce, CONTRACT_ADDR, 0, data.data(), data.size());

    // find the account's private key and sign on transaction using
    unsigned char *addr = channels.find(channel_id)->second.m_my_addr;

//    printf("addr : ");
//	    printf("%s", (unsigned char*)addr);
//    printf("\n");

    //addr = ::arr_to_bytes(addr, 40);
    addr = ::arr_to_bytes(owner, 40);
    std::vector<unsigned char> pubkey(addr, addr + 20);
    std::vector<unsigned char> seckey = accounts.find(pubkey)->second.get_seckey();
 
    printf("addr : ");
    for(int i=0; i<32; i++) {
	    printf("%02x", addr[i]);
    };printf("\n");

    printf("pubkey : ");
    for(int i=0; i<20; i++) {
	    printf("%02x", pubkey[i]);
    }printf("\n");

    printf("seckey : ");
    for(int i=0; i<32; i++) {
	    printf("%02x", seckey[i]);
    }

    printf("seckey : %s \n", (unsigned char*)seckey.data());
    tx.sign((unsigned char*)seckey.data());
    
    printf("===== CLOSE CHANNEL TX SIGN IS COMPLETE ===== \n");
    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    printf("===== CLOSE CHANNEL END IN ENCLAVE ===== \n");
    return;
}


void ecall_eject(unsigned int nonce, unsigned int pn, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    std::vector<unsigned char> data;

    /* encode ABI for calling "close_channel(uint256,uint256,uint256)" on the contract */
    sha3_context sha3_ctx;
    unsigned char *func = (unsigned char*)"eject(uint256,uint8,uint256[],uint256[],uint256)";
    unsigned char *msg32;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, func, strlen((char*)func));
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);


    /* data encoding */
    unsigned int total_headsize = 32 * 5;
    unsigned int stage;
    unsigned int head_pn, head_stage, head_ids, head_bals, head_v;
    unsigned int ids_size, bals_size, e, source_bal, target_bal;

    unsigned char *head_pn_bytes, *stage_bytes, *head_ids_bytes, *head_bals_bytes, *v_bytes;
    unsigned char *ids_size_bytes, *bals_size_bytes, *id_bytes, *source_bal_bytes, *target_bal_bytes;

    e = payments.find(pn)->second.m_related_channels.at(0).channel_id;
    stage = channels.find(e)->second.m_status;

    /*** cross-payment ***/
    if(stage == C_PRE || stage == C_POST)
	return;

    if(stage == PRE_UPDATE) {
        stage = 0;    // PRE_UPDATE on contract is 0, but PRE_UPDATE in channel.h is 1
    }
    else {
        stage = 1;
    }

    head_pn = pn;
    head_stage = stage;
    head_ids = total_headsize;
    head_bals = total_headsize + 32 + 32 * payments.find(pn)->second.m_related_channels.size();
    head_v = abs(payments.find(pn)->second.m_related_channels.at(0).amount);

    head_pn_bytes = create_uint256_argument(head_pn);
    stage_bytes = create_uint256_argument(head_stage);
    head_ids_bytes = create_uint256_argument(head_ids);
    head_bals_bytes = create_uint256_argument(head_bals);
    v_bytes = create_uint256_argument(head_v);


    data.insert(data.end(), msg32, msg32 + 4);

    data.insert(data.end(), head_pn_bytes, head_pn_bytes + 32);       // pn: head(pn) = enc(pn)
    data.insert(data.end(), stage_bytes, stage_bytes + 32); // stage: head(stage) = enc(stage)
    data.insert(data.end(), head_ids_bytes, head_ids_bytes + 32);       // ids: head(ids) = enc(len(head(pn) head(stage) head(ids) head(bals) head(v) tail(pn) tail(stage)))
    data.insert(data.end(), head_bals_bytes, head_bals_bytes + 32);       // bals: head(bals) = enc(len(head(pn) head(stage) head(ids) head(bals) head(v) tail(pn) tail(stage) tail(ids)))
    data.insert(data.end(), v_bytes, v_bytes + 32);       // v: head(v) = enc(v)

    ids_size = payments.find(pn)->second.m_related_channels.size();
    ids_size_bytes = create_uint256_argument(ids_size);
    data.insert(data.end(), ids_size_bytes, ids_size_bytes + 32);
    for(int i = 0; i < ids_size; i++) {
        e = payments.find(pn)->second.m_related_channels.at(i).channel_id;
        id_bytes = create_uint256_argument(e);
        data.insert(data.end(), id_bytes, id_bytes + 32);
    }

    bals_size = ids_size * 2;
    bals_size_bytes = create_uint256_argument(bals_size);
    data.insert(data.end(), bals_size_bytes, bals_size_bytes + 32);
    for(int i = 0; i < ids_size; i++) {
        e = payments.find(pn)->second.m_related_channels.at(i).channel_id;
        if(channels.find(e)->second.m_is_in == 0) { // owner is me
            source_bal = channels.find(e)->second.m_balance;
            target_bal = channels.find(e)->second.m_my_deposit - channels.find(e)->second.m_balance;
        }
        else {  // owner is not me
            source_bal = channels.find(e)->second.m_other_deposit - channels.find(e)->second.m_balance;
            target_bal = channels.find(e)->second.m_balance;
        }

        source_bal_bytes = create_uint256_argument(source_bal);
        target_bal_bytes = create_uint256_argument(target_bal);

        data.insert(data.end(), source_bal_bytes, source_bal_bytes + 32);
        data.insert(data.end(), target_bal_bytes, target_bal_bytes + 32);
    }


    Transaction tx(nonce, CONTRACT_ADDR, 0, data.data(), data.size());

    // find the account's private key and sign on transaction using
    unsigned char *addr = channels.find(e)->second.m_my_addr;
    addr = ::arr_to_bytes(addr, 40);
    std::vector<unsigned char> pubkey(addr, addr + 20);
    std::vector<unsigned char> seckey = accounts.find(pubkey)->second.get_seckey();

    tx.sign((unsigned char*)seckey.data());

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    return;
}


void ecall_get_num_open_channels(unsigned int *num_open_channels)
{
    /********************** test dummy **********************/
    // unsigned char *my_addr, *other_addr;
    // Channel channel1, channel2;

    // my_addr = (unsigned char*)"95809420428B4D972F6Cf2d5ab3F23ADA7039488";
    // other_addr = (unsigned char*)"83360d654B353Ca46342257D3e0eaC761cDEAc75";

    // channel1.m_id = 8;
    // channel1.m_is_in = 1;

    // channel1.m_status = POST_UPDATE;    // PENDING, IDLE, PRE_UPDATE, POST_UPDATE

    // channel1.m_my_addr = ::arr_to_bytes(my_addr, 40);
    // channel1.m_my_deposit = 0;
    // channel1.m_other_deposit = 90;
    // channel1.m_balance = 30;
    // channel1.m_locked_balance = 0;
    // channel1.m_other_addr = ::arr_to_bytes(other_addr, 40);

    // my_addr = (unsigned char*)"83360d654B353Ca46342257D3e0eaC761cDEAc75";
    // other_addr = (unsigned char*)"95809420428B4D972F6Cf2d5ab3F23ADA7039488";

    // channel2.m_id = 12;
    // channel2.m_is_in = 0;

    // channel2.m_status = POST_UPDATE;    // PENDING, IDLE, PRE_UPDATE, POST_UPDATE

    // channel2.m_my_addr = ::arr_to_bytes(my_addr, 40);
    // channel2.m_my_deposit = 70;
    // channel2.m_other_deposit = 0;
    // channel2.m_balance = 50;
    // channel2.m_locked_balance = 0;
    // channel2.m_other_addr = ::arr_to_bytes(other_addr, 40);

    // channels.insert(map_channel_value(8, channel1));
    // channels.insert(map_channel_value(12, channel2));
    /********************************************************/

    *num_open_channels = channels.size();
}


void ecall_get_open_channels(unsigned char *open_channels)
{
    //struct _channel *ochs = (struct _channel*)malloc(sizeof(struct _channel) * channels.size());

    channel data;
    std::map<unsigned int, Channel>::iterator iter;

    unsigned int cursor = 0;

    for (iter = channels.begin(); iter != channels.end(); ++iter) {
        data.m_id = iter->second.m_id;
        data.m_is_in = iter->second.m_is_in;
        data.m_status = iter->second.m_status;
        memcpy(data.m_my_addr, iter->second.m_my_addr, 20);
        data.m_my_deposit = iter->second.m_my_deposit;
        data.m_other_deposit = iter->second.m_other_deposit;
        data.m_balance = iter->second.m_balance;
        data.m_locked_balance = iter->second.m_locked_balance;

	/*** cross-payment ***/
	data.m_reserved_balance = iter->second.m_reserved_balance;

        memcpy(data.m_other_addr, iter->second.m_other_addr, 20);

        memcpy(open_channels + cursor, (unsigned char*)&data, sizeof(channel));
        cursor += sizeof(channel);
    }
}


void ecall_get_num_closed_channels(unsigned int *num_closed_channels)
{
    *num_closed_channels = channels.size();
}


void ecall_get_closed_channels(unsigned char *closed_chs)
{
    channel data;
    std::map<unsigned int, Channel>::iterator iter;

    unsigned int cursor = 0;

    for (iter = closed_channels.begin(); iter != closed_channels.end(); ++iter) {
        data.m_id = iter->second.m_id;
        data.m_is_in = iter->second.m_is_in;
        data.m_status = iter->second.m_status;
        memcpy(data.m_my_addr, iter->second.m_my_addr, 20);
        data.m_my_deposit = iter->second.m_my_deposit;
        data.m_other_deposit = iter->second.m_other_deposit;
        data.m_balance = iter->second.m_balance;
        data.m_locked_balance = iter->second.m_locked_balance;
        memcpy(data.m_other_addr, iter->second.m_other_addr, 20);

        memcpy(closed_chs + cursor, (unsigned char*)&data, sizeof(channel));
        cursor += sizeof(channel);
    }
}


void ecall_get_num_public_addrs(unsigned int *num_public_addrs)
{
    /********************** test dummy **********************/
    // unsigned char* paddr1 = (unsigned char*)"ABCDEABCDEABCDEABCDE";
    // unsigned char* sk1 = (unsigned char*)"ABCDEABCDEABCDEABCDEABCDEABCDEAB";
    // std::vector<unsigned char> p(paddr1, paddr1 + 20);
    // std::vector<unsigned char> s(sk1, sk1 + 32);

    // accounts.insert(map_account_value(p, Account(s)));

    // unsigned char* paddr2 = (unsigned char*)"VWXYZVWXYZVWXYZVWXYZ";
    // unsigned char* sk2 = (unsigned char*)"VWXYZVWXYZVWXYZVWXYZVWXYZVWXYZVW";
    // std::vector<unsigned char> p2(paddr2, paddr2 + 20);
    // std::vector<unsigned char> s2(sk2, sk2 + 32);

    // accounts.insert(map_account_value(p2, Account(s2)));
    /********************************************************/

    printf("accounts size : %d \n", accounts.size());
    *num_public_addrs = accounts.size();
}


void ecall_get_public_addrs(unsigned char *public_addrs)
{
    address data;
    std::map<std::vector<unsigned char>, Account>::iterator iter;
    std::vector<unsigned char> pubaddr;

    unsigned int cursor = 0;

    printf("GET PUBLIC ADDRS \n\n");
    // for (iter = accounts.begin(); iter != accounts.end(); ++iter) {
    //     pubaddr = iter->second.get_pubkey();
    //     memcpy(data.addr, pubaddr.data(), 20);
    //     memcpy(public_addrs + cursor, (unsigned char*)&data, sizeof(address));
    //     cursor += sizeof(address);
    // }

    for (iter = accounts.begin(); iter != accounts.end(); ++iter) {
        pubaddr = iter->first;
        memcpy(data.addr, pubaddr.data(), 20);
        memcpy(public_addrs + cursor, (unsigned char*)&data, sizeof(address));
        cursor += sizeof(address);
    }

    printf("public_addrs : ");
    for(int i=0; i<20; i++)
	    printf("%02x", public_addrs[i]);

}


void ecall_test_func(void)
{
    // unsigned char *original_msg = (unsigned char*)"TEST";
    // unsigned int msg_size = 7;
    // unsigned char *seckey = (unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd";
    // unsigned char signature[65];

    // // DirectPayment dp;

    // sign_message(original_msg, msg_size, seckey, signature);

    // printf("r: ");
    // for(int i = 0; i < 32; i++)
    //     printf("%02x", signature[i]);
    // printf("\n");

    // printf("s: ");
    // for(int i = 32; i < 64; i++)
    //     printf("%02x", signature[i]);
    // printf("\n");

    // int is_same = verify_message(signature, original_msg, msg_size, (unsigned char*)"d03a2cc08755ec7d75887f0997195654b928893e");
    // printf("IS SAME ? : %d\n", is_same);


    /******************* channel setting *******************/

    // unsigned char *my_addr, *other_addr;
    // Channel channel1;

    // my_addr = (unsigned char*)"d03a2cc08755ec7d75887f0997195654b928893e";
    // other_addr = (unsigned char*)"0b4161ad4f49781a821c308d672e6c669139843c";

    // channel1.m_id = 8;
    // channel1.m_is_in = 1;

    // channel1.m_status = POST_UPDATE;    // PENDING, IDLE, PRE_UPDATE, POST_UPDATE

    // channel1.m_my_addr = ::arr_to_bytes(my_addr, 40);
    // channel1.m_my_deposit = 0;
    // channel1.m_other_deposit = 90;
    // channel1.m_balance = 30;
    // channel1.m_locked_balance = 0;
    // channel1.m_other_addr = ::arr_to_bytes(other_addr, 40);

    // channels.insert(map_channel_value(8, channel1));

    // /******************* account setting *******************/

    // unsigned char* paddr = (unsigned char*)"d03a2cc08755ec7d75887f0997195654b928893e";
    // unsigned char* sk = (unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd";

    // paddr = ::arr_to_bytes(paddr, 40);
    // sk = ::arr_to_bytes(sk, 64);

    // std::vector<unsigned char> p(paddr, paddr + 20);
    // std::vector<unsigned char> s(sk, sk + 32);

    // accounts.insert(map_account_value(p, Account(s)));

    /*******************************************************/

    // unsigned char signature[65] = {0, };
    // unsigned char reply_signature[65] = {0, };
    // int is_success;

    // Message msg, reply_msg;

    // ecall_pay(8, 10, &is_success, (unsigned char*)&msg, signature);
    // ecall_paid((unsigned char*)&msg, signature, (unsigned char*)&reply_msg, reply_signature);
    // ecall_pay_accepted((unsigned char*)&reply_msg, reply_signature);

    // printf("msg.type: %d\n", reply_msg.type);
    // printf("msg.channel_id: %d\n", reply_msg.channel_id);
    // printf("msg.amount: %d\n", reply_msg.amount);

    unsigned char signature[65] = {0, };
    unsigned char *seckey = ::arr_to_bytes((unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd", 64);
    unsigned char *pubaddr = ::arr_to_bytes((unsigned char*)"d03a2cc08755ec7d75887f0997195654b928893e", 40);

    sign_message((unsigned char*)"TEST", 7, seckey, signature);

    for(int i = 0; i < 65; i++)
        printf("%02x", signature[i]);
    printf("\n");

    verify_message(0, signature, (unsigned char*)"TEST", 7, pubaddr);

    printf(" ######################### TEST ########################### \n");
}
