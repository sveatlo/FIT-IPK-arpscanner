#ifndef IPV6_H
#define IPV6_H

#include <string>
#include <string.h>
#include "definitions.h"

using namespace std;

class IPv6 {
public:
    IPv6(unsigned char* __address, string __address_string);

    unsigned char* get_address();
    string get_address_string();
private:
    unsigned char address[IPV6_LENGTH];
    string address_string;
};
#endif
