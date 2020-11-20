#ifndef CHANNEL_H
#define CHANNEL_H

#include <map>
#include <util.h>

enum channel_status {
    PENDING     = 0,
	IDLE		= 1,
	PRE_UPDATE	= 2,
	POST_UPDATE	= 3,
    CLOSED      = 4,
};


typedef struct _channel
{
    unsigned int m_id;
    unsigned int m_is_in;
    unsigned int m_status;
    unsigned char m_my_addr[20];
    unsigned int m_my_deposit;
    unsigned int m_other_deposit;
    unsigned int m_balance;
    unsigned int m_locked_balance;
    unsigned char m_other_addr[20];
    // unsigned char *m_other_ip;   this field must be requested from the server newly
    // unsigned int m_other_port;   this field must be requested from the server newly
} channel;


class Channel {
    public:
        Channel() {m_counter = 0;};
        Channel(unsigned int t_id,
                unsigned char *t_my_addr,
                unsigned char *t_other_addr,
                bool t_is_in,
                unsigned int t_deposit
                )
                : m_id(t_id)
                , m_is_in(t_is_in)
        {
            m_my_addr = ::arr_to_bytes(t_my_addr, 40);
            m_other_addr = ::arr_to_bytes(t_other_addr, 40);

            m_status = (m_id == -1) ? PENDING:IDLE;

            if(m_is_in == true) {
                m_my_deposit = 0;
                m_other_deposit = t_deposit;
                m_balance = 0;
                m_locked_balance = 0;
            }
            else {
                m_my_deposit = t_deposit;
                m_other_deposit = 0;
                m_balance = t_deposit;
                m_locked_balance = 0;
            }

            m_counter = 0;
        };

        int pay(unsigned int amount);
        int paid(unsigned int amount);

        void transition_to_pre_update(void);
        void transition_to_post_update(void);
        void transition_to_idle(void);

        unsigned int get_balance(void);


        unsigned int m_id;
        bool m_is_in;
        channel_status m_status;
        unsigned char *m_my_addr;
        unsigned int m_my_deposit;
        unsigned int m_other_deposit;
        unsigned int m_balance;
        unsigned int m_locked_balance;
        unsigned char *m_other_addr;
        unsigned char *m_other_ip;
        unsigned int m_other_port;

        unsigned int m_counter;
};

using namespace std;

typedef std::map<unsigned int, Channel> map_channel;
typedef map_channel::value_type map_channel_value;

extern map_channel channels;
extern map_channel closed_channels;

#endif