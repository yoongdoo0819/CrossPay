#include <account.h>
#include <channel.h>
#include <payment.h>
#include <util.h>

#include "enclave.h"
#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"


void ecall_store_account_data(char *keyfile)
{
    /********************** test dummy **********************/
    // unsigned char *addr = (unsigned char*)"78902c58006916201F65f52f7834e467877f0500";
    // unsigned char *sk = (unsigned char*)"3038465f2b9be0048caa9f33e25b5dc50252f04c078aaddfbea74f26cdeb9f3c";

    // unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    // unsigned char *sk_bytes = ::arr_to_bytes(sk, 64);

    // std::vector<unsigned char> p(addr_bytes, addr_bytes + 20);
    // std::vector<unsigned char> s(sk_bytes, sk_bytes + 32);

    // accounts.insert(map_account_value(p, Account(s)));

    // unsigned char *addr2 = (unsigned char*)"83360d654B353Ca46342257D3e0eaC761cDEAc75";
    // unsigned char *sk2 = (unsigned char*)"902424638988c6fd60caa0453735f583f4bfe124233366201a419202963ddc06";

    // unsigned char *addr_bytes2 = ::arr_to_bytes(addr2, 40);
    // unsigned char *sk_bytes2 = ::arr_to_bytes(sk2, 64);

    // std::vector<unsigned char> p2(addr_bytes2, addr_bytes2 + 20);
    // std::vector<unsigned char> s2(sk_bytes2, sk_bytes2 + 32);

    // accounts.insert(map_account_value(p2, Account(s2)));
    /********************************************************/


    std::map<std::vector<unsigned char>, Account>::iterator iter;
    std::vector<unsigned char> seckey;
    uint32_t size;

    unsigned char data[32], sealed_log[600];

    ocall_remove_key_file(keyfile);

    for (iter = accounts.begin(); iter != accounts.end(); ++iter) {
        seckey = iter->second.get_seckey();
        std::copy(seckey.begin(), seckey.end(), data);   // copy secret key to 'data'

        size = sgx_calc_sealed_data_size((const uint32_t)0, (const uint32_t)32);
        sgx_seal_data(0, NULL, 32, (uint8_t *)data, size, (sgx_sealed_data_t*)sealed_log);

        printf("PRIVATE KEY IS SEALED SUCCESSFULLY !! (SEALED DATA SIZE: %d)\n", size);
	for(int i = 0; i < 32; i++)
		printf("%02x", data[i]);
    	printf("\n");

        ocall_store_sealed_seckey(keyfile, sealed_log);
    }

    return;
}


void ecall_store_channel_data(char *chfile)
{
    /********************** test dummy **********************/
    // unsigned char *my_addr, *other_addr;
    // Channel channel1, channel2;

    // my_addr = (unsigned char*)"78902c58006916201F65f52f7834e467877f0500";
    // other_addr = (unsigned char*)"0b4161ad4f49781a821C308D672E6c669139843C";

    // channel1.m_id = 12;
    // channel1.m_is_in = 1;

    // channel1.m_status = IDLE;    // PENDING, IDLE, PRE_UPDATE, POST_UPDATE

    // channel1.m_my_addr = ::arr_to_bytes(my_addr, 40);
    // channel1.m_my_deposit = 0;
    // channel1.m_other_deposit = 70;
    // channel1.m_balance = 0;
    // channel1.m_locked_balance = 0;
    // channel1.m_other_addr = ::arr_to_bytes(other_addr, 40);

    // channels.insert(map_channel_value(12, channel1));

    // my_addr = (unsigned char*)"0b4161ad4f49781a821C308D672E6c669139843C";
    // other_addr = (unsigned char*)"78902c58006916201F65f52f7834e467877f0500";

    // channel2.m_id = 12;
    // channel2.m_is_in = 0;

    // channel2.m_status = IDLE;    // PENDING, IDLE, PRE_UPDATE, POST_UPDATE

    // channel2.m_my_addr = ::arr_to_bytes(my_addr, 40);
    // channel2.m_my_deposit = 70;
    // channel2.m_other_deposit = 0;
    // channel2.m_balance = 70;
    // channel2.m_locked_balance = 0;
    // channel2.m_other_addr = ::arr_to_bytes(other_addr, 40);

    // channels.insert(map_channel_value(12, channel2));
    /********************************************************/


    channel data;

    std::map<unsigned int, Channel>::iterator iter;
    uint32_t size;

    unsigned char sealed_log[700];

    ocall_remove_channel_file(chfile);

    for (iter = channels.begin(); iter != channels.end(); ++iter) {
        data.m_id = iter->second.m_id;
        data.m_is_in = iter->second.m_is_in;
        data.m_status = iter->second.m_status;
        memcpy(data.m_my_addr, iter->second.m_my_addr, 20);
        data.m_my_deposit = iter->second.m_my_deposit;
        data.m_other_deposit = iter->second.m_other_deposit;
        data.m_balance = iter->second.m_balance;
        data.m_locked_balance = iter->second.m_locked_balance;
        memcpy(data.m_other_addr, iter->second.m_other_addr, 20);

        size = sgx_calc_sealed_data_size((const uint32_t)0, (const uint32_t)sizeof(channel));  // sealed log size = 628
        sgx_seal_data(0, NULL, sizeof(channel), (uint8_t *)&data, size, (sgx_sealed_data_t*)sealed_log);

        printf("CHANNEL DATA IS SEALED SUCCESSFULLY !! (SEALED DATA SIZE: %d)\n", size);
        ocall_store_sealed_channel_data(chfile, sealed_log);
    }

    return;
}
