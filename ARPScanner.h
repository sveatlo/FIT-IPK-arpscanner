#ifndef ARPSCANNER_H
#define ARPSCANNER_H

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include "Interface.h"

using namespace std;

class ARPScanner {
public:
    ARPScanner(string __interface, string __output_file);
    ~ARPScanner();

    static bool keep_scanning;

    void clean(bool);

private:
    Interface interface;
    ofstream output_file;
    int arp_send_sd = 0;
    int arp_rcv_sd = 0;
    int icmpv6_send_sd = 0;
    int icmpv6_rcv_sd = 0;
    map<string, map<string, set<string>>> xml_data; // {mac: {ipv4: ipv4_address, ipv6: ipv6_address}}

    void ipv4_scan();
    void bind_arp();
    void send_arp_request(uint32_t, IPv4*);
    void recv_arp_responses();

    void ipv6_scan();
    void bind_icmpv6();
    void send_icmpv6_request(string);

    void print_out_data();
};


struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

typedef struct _pktinfo6 {
    struct in6_addr ipi6_addr;
    int ipi6_ifindex;
} pktinfo6;

#endif
