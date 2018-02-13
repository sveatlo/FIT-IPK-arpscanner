#include <arpa/inet.h>
#include <string>
#include "Utils.h"
#include "IPv4.h"

IPv4::IPv4(unsigned char* __address, unsigned char* __netmask) {
    memcpy(this->address, __address, IPV4_LENGTH);
    memcpy(this->netmask, __netmask, IPV4_LENGTH);

    char caddress[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, __address, caddress, sizeof(caddress));

    char cnetmask[33];
    sprintf(cnetmask, "%d.%d.%d.%d", (unsigned char)__netmask[0], (unsigned char)__netmask[1], (unsigned char)__netmask[2], (unsigned char)__netmask[3]);

    this->address_string = string(caddress);
    this->netmask_string = string(cnetmask);
}


uint32_t IPv4::get_address() {
    return Utils::ip_to_int(this->address_string);
}

uint32_t IPv4::get_netmask() {
    return Utils::ip_to_int(this->netmask_string);
}

string IPv4::get_address_string() {
    return this->address_string;
}
string IPv4::get_netmask_string() {
    return this->netmask_string;
}
