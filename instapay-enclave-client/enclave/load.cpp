#include <account.h>
#include <channel.h>
#include <payment.h>
#include <util.h>

#include "enclave.h"
#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"


void ecall_load_account_data(unsigned char *sealed_seckey)
{
    uint32_t unsealed_size = 32;
    uint8_t unsealed_seckey[32];

    sgx_unseal_data((sgx_sealed_data_t *)sealed_seckey, NULL, 0, (uint8_t *)&unsealed_seckey, &unsealed_size);

    printf("UNSEALED SECKEY: ");
    for(int i = 0; i < 32; i++)
        printf("%02x", unsealed_seckey[i]);
    printf("\n");

    std::vector<unsigned char> seckey(unsealed_seckey, unsealed_seckey + 32);
    Account account(seckey);

    std::vector<unsigned char> pubkey = account.get_pubkey();

    accounts.insert(map_account_value(pubkey, account));

    return;
}


void ecall_load_channel_data(unsigned char *sealed_channel_data)
{
    uint32_t unsealed_size = sizeof(channel);
    channel unsealed_channel_data;

    sgx_unseal_data((sgx_sealed_data_t *)sealed_channel_data, NULL, 0, (uint8_t *)&unsealed_channel_data, &unsealed_size);


    printf("=========== UNSEALED CHANNEL DATA ===========\n");
    printf("channel id: %d\n", unsealed_channel_data.m_id);
    printf("is in ?: %d\n", unsealed_channel_data.m_is_in);
    printf("status: %d\n", unsealed_channel_data.m_status);

    printf("my address: ");
    for(int i = 0; i < 20; i++)
        printf("%02x", unsealed_channel_data.m_my_addr[i]);
    printf("\n");

    printf("my deposit: %d\n", unsealed_channel_data.m_my_deposit);
    printf("other deposit: %d\n", unsealed_channel_data.m_other_deposit);
    printf("my balance: %d\n", unsealed_channel_data.m_balance);
    printf("locked balance: %d\n", unsealed_channel_data.m_locked_balance);

    printf("other address: ");
    for(int i = 0; i < 20; i++)
        printf("%02x", unsealed_channel_data.m_other_addr[i]);

    printf("\n=============================================\n");


    Channel ch;

    ch.m_id = unsealed_channel_data.m_id;
    ch.m_is_in = unsealed_channel_data.m_is_in;
    ch.m_status = (channel_status)unsealed_channel_data.m_status;

    ch.m_my_addr = ::copy_bytes(unsealed_channel_data.m_my_addr, 20);
    
    ch.m_my_deposit = unsealed_channel_data.m_my_deposit;
    ch.m_other_deposit = unsealed_channel_data.m_other_deposit;
    ch.m_balance = unsealed_channel_data.m_balance;
    ch.m_locked_balance = unsealed_channel_data.m_locked_balance;

    ch.m_other_addr = ::copy_bytes(unsealed_channel_data.m_other_addr, 20);
    ch.m_counter = 0;

    channels.insert(map_channel_value(ch.m_id, ch));

    return;
}