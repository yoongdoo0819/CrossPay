#include <channel.h>


int Channel::pay(unsigned int amount)
{
    m_balance -= amount;
    return true;
}


int Channel::paid(unsigned int amount)
{
    m_balance += amount;
    return true;
}


void Channel::transition_to_pre_update()
{
    m_status = PRE_UPDATE;
}


void Channel::transition_to_post_update()
{
    m_status = POST_UPDATE;
}


void Channel::transition_to_idle()
{
    m_status = IDLE;
}


unsigned int Channel::get_balance()
{
    return m_balance;
}

/*** cross-payment ***/
void Channel::transition_to_cross_pre_update()
{
    m_cross_status = C_PRE;
}


void Channel::transition_to_cross_post_update()
{
    m_cross_status = C_POST;
}

void Channel::transition_to_cross_idle()
{
    m_cross_status = C_IDLE;
}


map_channel channels;
map_channel closed_channels;
