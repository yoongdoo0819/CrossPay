#include <payment.h>


void Payment::add_element(unsigned int channel_id, int amount)
{
    Related r = {channel_id, amount};
    m_related_channels.push_back(r);
}


map_payment payments;