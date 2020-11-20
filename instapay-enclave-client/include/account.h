#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <vector>
#include <map>
#include <util.h>

#if defined(__cplusplus)
extern "C" {
#endif

#include <secp256k1.h>
#include <sha3.h>

#if defined(__cplusplus)
}
#endif

using namespace std;


typedef struct _address
{
    unsigned char addr[20];
} address;


class Account {
    public:
        Account(std::vector<unsigned char> t_seckey) {
            m_seckey = t_seckey;
        };

        std::vector<unsigned char> get_pubkey(void);
        std::vector<unsigned char> get_seckey(void);

    private:
        std::vector<unsigned char> m_seckey;
};

typedef std::map<std::vector<unsigned char>, Account> map_account;
typedef map_account::value_type map_account_value;

extern map_account accounts;

#endif