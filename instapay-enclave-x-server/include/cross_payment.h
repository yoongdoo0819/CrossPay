#ifndef CROSS_PAYMENT_H
#define CROSS_PAYMENT_H

#include <set>
#include <map>
#include <vector>
#include <util.h>

enum cross_payment_status {
	NONE      = 0,
	PREPARED  = 1,
	COMMITTED = 2,
	REFUNDED  = 3,
};

using namespace std;

class Cross_Payment {
    public:
	Cross_Payment() {}

        Cross_Payment(unsigned int t_payment_num, unsigned char *chain1Server, unsigned char *chain1Sender, unsigned char *chain1Receiver, unsigned int chain1Amount, unsigned char *chain2Server, unsigned char *chain2Sender, unsigned char *chain2Receiver, unsigned int chain2Amount)
		: m_cross_payment_num(t_payment_num)
        {

		m_chain1Server = ::arr_to_bytes(chain1Server, 40);
		m_chain1Sender = ::arr_to_bytes(chain1Sender, 40);
		m_chain1Receiver = ::arr_to_bytes(chain1Receiver, 40);
		m_chain1Amount = chain1Amount;
	
		m_chain2Server = ::arr_to_bytes(chain2Server, 40);
		m_chain2Sender = ::arr_to_bytes(chain2Sender, 40);
		m_chain2Receiver = ::arr_to_bytes(chain1Receiver, 40);
		m_chain2Amount = chain2Amount;
		
		m_cross_status = NONE;
        };

        static unsigned int acc_cross_payment_num;

        void register_participant(unsigned char *addr);
        void update_preparedServer(unsigned char *addr);
        void update_committedServer(unsigned char *addr);
        int check_unanimity(int which_list);
        //void update_status_to_success(void);

	cross_payment_status m_cross_status;

	unsigned int m_chain1Server_prepared;
	unsigned int m_chain2Server_prepared;

	unsigned int m_chain1Server_committed;
	unsigned int m_chain2Server_committed;

    private:
        unsigned int m_cross_payment_num;

	unsigned char *m_chain1Server;
        unsigned char *m_chain1Sender;
        unsigned char *m_chain1Receiver;
	unsigned int m_chain1Amount;

	unsigned char *m_chain2Server;
        unsigned char *m_chain2Sender;
        unsigned char *m_chain2Receiver;
	unsigned int m_chain2Amount;

//	unsigned int m_chain1Server_verification;
//	unsigned int m_chain2Server_verification;

        std::set< vector<unsigned char> > m_participants;
        std::set< vector<unsigned char> > m_prepared_server;
        std::set< vector<unsigned char> > m_committed_server;
	
//        cross_payment_status m_cross_status;
};

typedef std::map<unsigned int, Cross_Payment> map_cross_payment;
typedef map_cross_payment::value_type map_cross_payment_value;

extern map_cross_payment cross_payments;

#endif
