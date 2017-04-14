#ifndef ARPSCANNER_H
#define ARPSCANNER_H

#include "arpa/inet.h"
#include "sys/ioctl.h"
#include "netpacket/packet.h"
#include "net/ethernet.h"
#include "net/if_arp.h"
#include <fstream>
#include <string>

// Define some constants.
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>

using namespace std;

class ARPScanner {
public:
    ARPScanner(string __interface, string __output_file);

private:
    string interface;
    ofstream output_file;
    int if_index;
    uint8_t* src_mac;
    uint32_t ipv4_address;

    void ipv4_scan();
    void send_arp_request(uint32_t ipv4_address);
};

#endif
