#ifndef PAYMENT_H
#define PAYMENT_H

#include <set>
#include <map>
#include <vector>
#include <util.h>

enum payment_status {
	FAILED	= 0,
	SUCCESS	= 1,
};

using namespace std;

class Payment {
    public:
        Payment(unsigned int t_payment_num,
                unsigned char *t_sender,
                unsigned char *t_receiver,
                unsigned int t_amount
                )
                : m_payment_num(t_payment_num)
                , m_amount(t_amount)                
        {
            m_sender = ::arr_to_bytes(t_sender, 40);
            m_receiver = ::arr_to_bytes(t_receiver, 40);
            m_status = FAILED;
        };

        static unsigned int acc_payment_num;

        void register_participant(unsigned char *addr);
        void update_addrs_sent_agr(unsigned char *addr);
        void update_addrs_sent_upt(unsigned char *addr);
        int check_unanimity(int which_list);
        void update_status_to_success(void);

    private:
        unsigned int m_payment_num;
        unsigned char *m_sender;
        unsigned char *m_receiver;
        unsigned int m_amount;
        std::set< vector<unsigned char> > m_participants;
        std::set< vector<unsigned char> > m_addrs_sent_agr;
        std::set< vector<unsigned char> > m_addrs_sent_upt;
        payment_status m_status;
};

typedef std::map<unsigned int, Payment> map_payment;
typedef map_payment::value_type map_payment_value;

extern map_payment payments;

#endif