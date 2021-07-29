#ifndef PAYMENT_H
#define PAYMENT_H

#include <vector>
#include <map>
#include <util.h>

enum payment_status {
	INIT	= 0,
	END	= 1,
};

using namespace std;

typedef struct related {
    unsigned int channel_id;
    int amount;  // can be + or - depending on the path
} Related;

class Payment {
    public:
        Payment(unsigned int t_payment_num) {
            m_payment_num = t_payment_num;
	    m_status = INIT;
        };

        std::vector<Related> m_related_channels;
        
        void add_element(unsigned int channel_id, int amount);

	unsigned int m_status;

    private:
        unsigned int m_payment_num;
};

typedef std::map<unsigned int, Payment> map_payment;
typedef map_payment::value_type map_payment_value;

extern map_payment payments;

#endif
