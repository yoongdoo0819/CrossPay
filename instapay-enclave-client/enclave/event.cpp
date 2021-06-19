#include <string.h>
#include <stdint.h>
#include <cstring>

#include "enclave.h"
#include "enclave_t.h"

#include <account.h>
#include <channel.h>
#include <util.h>


using namespace std;


void ecall_receive_create_channel(unsigned int channel_id, unsigned char *owner, unsigned char *receiver, unsigned int deposit)
{
    unsigned char *owner_addr_bytes = ::arr_to_bytes(owner, 40);
    unsigned char *receiver_addr_bytes = ::arr_to_bytes(receiver, 40);
    std::vector<unsigned char> owner_addr(owner_addr_bytes, owner_addr_bytes + 20);
    std::vector<unsigned char> receiver_addr(receiver_addr_bytes, receiver_addr_bytes + 20);

    if(accounts.find(owner_addr) == accounts.end() && accounts.find(receiver_addr) == accounts.end())
        return;

    Channel *channel;

    if(accounts.find(owner_addr) != accounts.end())
        channel = new Channel(channel_id, owner, receiver, false, deposit);
    else
        channel = new Channel(channel_id, receiver, owner, true, deposit);

    channels.insert(map_channel_value(channel_id, *channel));

    printf("CHANNEL CREATED ! \n");
    return;
}


void ecall_receive_close_channel(unsigned int channel_id, unsigned int owner_bal, unsigned int receiver_bal)
{
    if(channels.find(channel_id) != channels.end()) {
        closed_channels.insert(map_channel_value(channel_id, channels.find(channel_id)->second));
        channels.erase(channel_id);
    }
}
