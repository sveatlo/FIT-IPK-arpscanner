#ifndef INTERFACE_H
#define INTERFACE_H

#include <string>
#include <vector>
#include "IPv4.h"
#include "IPv6.h"
#include "definitions.h"

using namespace std;

class Interface {
public:
    Interface();
    void populate_info(string __name);
    void print_info();

    unsigned char* get_mac_address();
    string get_mac_string();
    int get_index();
    vector<IPv4*> get_ipv4_addresses();
    vector<IPv6*> get_ipv6_addresses();

private:
    string name;
    int index;
    unsigned char mac[MAC_LENGTH];
    string mac_string;

    vector<IPv4*> ipv4_addresses;
    vector<IPv6*> ipv6_addresses;
};

#endif
