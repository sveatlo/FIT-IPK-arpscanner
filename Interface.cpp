#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h> /* the L2 protocols */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "Interface.h"
#include "Utils.h"

#include <bitset>

using namespace std;

Interface::Interface() { }

void Interface::populate_info(string __name) {
    this->name = __name;

    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) != 0) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    struct ifaddrs * ifa;
    int n;
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if(!ifa->ifa_addr || !ifa->ifa_addr->sa_family) {
            continue;
        }
        int family = ifa->ifa_addr->sa_family;
        if(string(ifa->ifa_name) != this->name || ifa->ifa_addr == NULL) {
            continue;
        }

        switch (family) {
            case AF_PACKET:
                {
                    // save struct containing MAC address
                    struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                    // copy mac address to instance variable
                    memcpy(this->mac, s->sll_addr, MAC_LENGTH);
                    // create and save string
                    char mac_cstring[MAC_LENGTH*2+5];
                    int len = 0;
                    for(int i = 0; i < 6; i++) {
                        len += sprintf(mac_cstring+len, "%02X%s",s->sll_addr[i],i < 5 ? ":":"");
                    }
                    this->mac_string = string(mac_cstring);
                    break;
                }
            case AF_INET:
                {
                    unsigned char address[IPV4_LENGTH], netmask[IPV4_LENGTH];
                    // copy ipv4 addr
                    memcpy(address, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr), IPV4_LENGTH);
                    // process netmask
                    memcpy(netmask, (ifa->ifa_netmask->sa_data) + 2, IPV4_LENGTH);

                    IPv4* ipv4_address = new IPv4(address, netmask);
                    this->ipv4_addresses.push_back(ipv4_address);

                    break;
                }
            case AF_INET6:
                {
                    //copy ipv6 address
                    unsigned char ipv6_address_arr[IPV6_LENGTH];
                    memcpy(ipv6_address_arr, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, IPV6_LENGTH);
                    //create ipv6 string
                    char address[INET6_ADDRSTRLEN];
                    inet_ntop(family, &((sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, address, sizeof(address));
                    string ipv6_string = string(address);

                    //if start with fe80 => is link-local
                    if(ipv6_string.find("fe80") == 0) {
                        IPv6* ipv6_address = new IPv6(ipv6_address_arr, ipv6_string);
                        this->ipv6_addresses.push_back(ipv6_address);
                    }
                    break;
                }
        }
    }
    freeifaddrs(ifaddr);

    // get interface index
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, 0);
    if (sd <= 0) {
        Utils::print_error(101);
    }
    if (this->name.length() > (IFNAMSIZ - 1)) {
        Utils::print_error(101);
    }
    strcpy(ifr.ifr_name, this->name.c_str());

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        if (sd > 0) {
            close(sd);
        }
        Utils::print_error(101);
    }
    this->index = ifr.ifr_ifindex;

    close(sd);
}

unsigned char* Interface::get_mac_address() {
    return this->mac;
}

string Interface::get_mac_string() {
    return this->mac_string;
}

int Interface::get_index() {
    return this->index;
}

void Interface::print_info() {
    cout << "Interface info: " << endl;
    cout << "\tName: " << this->name << endl;
    cout << "\tInterface index: " << this->index << endl;
    cout << "\tMAC address: " << this->mac_string << endl;
    for(auto &ipv4_address : this->ipv4_addresses) {
        cout << "\tIPv4 address: " << ipv4_address->get_address_string() << endl;
        cout << "\tIPv4 netmask: " << ipv4_address->get_netmask_string() << endl;
    }
    for(auto &ipv6_address : this->ipv6_addresses) {
        cout << "\tIPv6 address: " << ipv6_address->get_address_string() << endl;
    }
}

vector<IPv4*> Interface::get_ipv4_addresses() {
    return this->ipv4_addresses;
}

vector<IPv6*> Interface::get_ipv6_addresses() {
    return this->ipv6_addresses;
}
