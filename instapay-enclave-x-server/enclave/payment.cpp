#include <payment.h>


void Payment::register_participant(unsigned char *addr)
{
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    m_participants.insert(std::vector<unsigned char>(addr_bytes, addr_bytes + 20));
}


void Payment::update_addrs_sent_agr(unsigned char *addr)
{
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    m_addrs_sent_agr.insert(std::vector<unsigned char>(addr_bytes, addr_bytes + 20));
}


void Payment::update_addrs_sent_upt(unsigned char *addr)
{
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    m_addrs_sent_upt.insert(std::vector<unsigned char>(addr_bytes, addr_bytes + 20));
}


int Payment::check_unanimity(int which_list)
{
    if(which_list == 0)
        return (m_participants == m_addrs_sent_agr);
    else if(which_list == 1)
        return (m_participants == m_addrs_sent_upt);
}


void Payment::update_status_to_success(void)
{
    m_status = SUCCESS;
}


map_payment payments;