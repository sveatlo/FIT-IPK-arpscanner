#ifndef UTILS_H
#define UTILS_H

#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <string>

using namespace std;

class Utils {
public:
    static void print_error(int code);
    static uint32_t ip_to_int(const std::string ip);
    static string int_to_ip(const uint32_t addr);
    static unsigned int rotr(const unsigned int value, int shift);
    static unsigned int rotl(const unsigned int value, int shift);
    static uint16_t checksum (uint16_t *, int);
    static uint16_t icmp6_checksum (struct ip6_hdr, struct icmp6_hdr, uint8_t *, int);
};


#endif
