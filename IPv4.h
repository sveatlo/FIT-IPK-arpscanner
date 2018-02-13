#ifndef IPV4_H
#define IPV4_H

#include <string>
#include <string.h>
#include "definitions.h"

using namespace std;

class IPv4 {
public:
    IPv4(unsigned char* __address, unsigned char* __netmask);

    uint32_t get_address();
    uint32_t get_netmask();
    string get_address_string();
    string get_netmask_string();
private:
    unsigned char address[IPV4_LENGTH];
    char netmask[IPV4_LENGTH];
    string address_string;
    string netmask_string;

};
#endif
