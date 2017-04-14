#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include "Utils.h"

using namespace std;

void Utils::print_error(int code) {
    std::map<int, std::string> error_strings = {
            {0, "Run arp-scanner as root, stupid!"},
            {1, "Invalid arguments"},
            {2, "Cannot open output file"}
    };

    cerr << "\033[1;31m" << (error_strings.count(code) > 0 ? error_strings[code] : "Unknown error") << "\033[0m\n";
    exit(code);
}

uint32_t Utils::ip_to_int(const std::string ip) {
    int a, b, c, d;
    uint32_t addr = 0;

    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        Utils::print_error(101);
    }

    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

// 1 2 3 4
string Utils::int_to_ip(const uint32_t addr) {
    stringstream ss;
    ss << (addr >> 24) << "." << (Utils::rotr(addr, 24) >> 24) << "." << (Utils::rotr(addr, 16) >> 24) << "." << (Utils::rotr(addr, 8) >> 24);
    return ss.str();
}

unsigned int Utils::rotr(const unsigned int value, int shift) {
    if ((shift &= sizeof(value)*8 - 1) == 0)
      return value;
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

unsigned int Utils::rotl(const unsigned int value, int shift) {
    if ((shift &= sizeof(value)*8 - 1) == 0)
      return value;
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}
