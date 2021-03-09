#include <cross_payment.h>
#include "enclave.h"

void Cross_Payment::register_participant(unsigned char *addr)
{
	/*
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    m_participants.insert(std::vector<unsigned char>(addr_bytes, addr_bytes + 20));
    */
}


void Cross_Payment::update_preparedServer(unsigned char *addr)
{
//    m_prepared_server.insert(std::vector<unsigned char>(addr, addr+20));
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    m_prepared_server.insert(std::vector<unsigned char>(addr_bytes, addr_bytes + 20));
}


void Cross_Payment::update_committedServer(unsigned char *addr)
{
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    m_committed_server.insert(std::vector<unsigned char>(addr_bytes, addr_bytes + 20));
}


int Cross_Payment::check_unanimity(int which_list)
{
    printf("participants : %s \n", m_participants);
    printf("prepared_server : %s \n", m_prepared_server);
    if(which_list == 0)  {
        return (m_participants == m_prepared_server);
    }
    else if(which_list == 1)
        return (m_participants == m_committed_server);
}

/*
void Payment::update_status_to_success(void)
{
    m_status = SUCCESS;
}
*/

map_cross_payment cross_payments;
