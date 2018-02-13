#include <arpa/inet.h>
#include <string>
#include "Utils.h"
#include "IPv6.h"

IPv6::IPv6(unsigned char* __address, string __address_string) {
    memcpy(this->address, __address, IPV6_LENGTH);
    this->address_string = __address_string;
}


unsigned char* IPv6::get_address() {
    return this->address;
}

string IPv6::get_address_string() {
    return this->address_string;
}
