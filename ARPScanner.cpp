#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>    // struct icmp6_hdr and ICMP6_ECHO_REQUEST
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "ARPScanner.h"
#include "definitions.h"
#include "Interface.h"
#include "IPv4.h"
#include "Utils.h"

using namespace std;

bool ARPScanner::keep_scanning = true; // initialize value
ofstream output_file;
vector<ARPScanner*> arp_scanners;
bool sigint_handled = false;

void sig_handler(int signal) {
    if(sigint_handled) return;
    sigint_handled = true;
    ARPScanner::keep_scanning = false;
    cout << "\nScanning will soon be interrupted..." << endl;

    for(auto &scanner : arp_scanners) {
        scanner->clean(false);
    }
}

ARPScanner::ARPScanner(string __interface, string __file_name) {
    signal(SIGINT, sig_handler);
    this->output_file.open(__file_name, ios::out | ios::trunc);

    if(!this->output_file) {
        Utils::print_error(2);
    }
    arp_scanners.push_back(this);

    this->interface.populate_info(__interface);
    this->interface.print_info();
    thread ipv4_scan(&ARPScanner::ipv4_scan, this);
    thread ipv6_scan(&ARPScanner::ipv6_scan, this);
    while(ARPScanner::keep_scanning) {
        sleep(1); // busy waiting
    }
    ipv4_scan.detach();
    ipv6_scan.detach();
    this->print_out_data();
}

ARPScanner::~ARPScanner() {
    this->clean(true);
}

void ARPScanner::clean(bool close_file) {
    if(this->arp_send_sd > 0) {
        cout << "Closing ARP sending socket..." << endl;
        close(this->arp_send_sd);
        this->arp_send_sd = 0;
    }

    if(this->arp_rcv_sd > 0) {
        cout << "Closing ARP receiving socket..." << endl;
        close(this->arp_rcv_sd);
        this->arp_rcv_sd = 0;
    }

    if(this->icmpv6_send_sd > 0) {
        cout << "Closing ICMPv6 sending socket..." << endl;
        close(this->icmpv6_send_sd);
        this->icmpv6_send_sd = 0;
    }

    if(this->icmpv6_rcv_sd > 0) {
        cout << "Closing ICMPv6 receiving socket..." << endl;
        close(this->icmpv6_rcv_sd);
        this->icmpv6_rcv_sd = 0;
    }

    if(close_file && this->output_file && this->output_file.is_open()) {
        this->output_file.close();
    }
}

void ARPScanner::ipv4_scan() {
    this->bind_arp();
    thread t(&ARPScanner::recv_arp_responses, this);
    for(auto &src : this->interface.get_ipv4_addresses()) {
        uint32_t ipv4_address = src->get_address();
        uint32_t netmask = src->get_netmask();
        uint32_t net_lower = (ipv4_address & netmask);
        uint32_t net_upper = (net_lower | (~netmask));

        for(uint32_t dst = net_lower + 1; dst <= net_upper - 1; dst++) {
            if(dst != ipv4_address) {
                this->send_arp_request(dst, src);
            }
        }
    }
    t.join();
}

void ARPScanner::bind_arp() {
    // Submit request for a raw socket descriptor.
    this->arp_send_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (this->arp_send_sd <= 0) {
        Utils::print_error(102);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = this->interface.get_index();
    if (bind(this->arp_send_sd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        if(this->arp_send_sd > 0) {
            close(this->arp_send_sd);
        }
        Utils::print_error(102);
    }

    if ((this->arp_rcv_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        Utils::print_error(104);
    }

    // // TODO: fix non-working receiving timeout
    // struct timeval wait;
    // wait.tv_sec  = 2;
    // wait.tv_usec = 0;
    // //set socket timeout
    // if(setsockopt(this->arp_rcv_sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&wait, sizeof(struct timeval)) < 0) {
    //     Utils::print_error(104);
    // }
}

void ARPScanner::bind_icmpv6() {
    if ((icmpv6_send_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    // Submit request for a raw socket descriptor to receive packets.
    if ((icmpv6_rcv_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        Utils::print_error(105);
    }

    struct timeval wait;
    int timeout = 2;
    wait.tv_sec  = timeout;
    wait.tv_usec = 0;
    setsockopt (icmpv6_rcv_sd, SOL_SOCKET, SO_RCVTIMEO, (char *) &wait, sizeof (struct timeval));
}

void ARPScanner::send_arp_request(uint32_t dst_address, IPv4* src_address) {
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = this->interface.get_index();
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    ssize_t ret;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    unsigned char* mac = this->interface.get_mac_address();
    memcpy(send_req->h_source, mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    uint32_t src_ip = htonl(src_address->get_address());
    uint32_t dst_ip = htonl(dst_address);
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(this->arp_send_sd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        Utils::print_error(103);
    }
}

void ARPScanner::recv_arp_responses() {
    struct arp_header *arp_res;

    while (ARPScanner::keep_scanning) {
        // Allocate memory for the ethernet frame
        uint8_t *ether_frame = (uint8_t *) malloc (IP_MAXPACKET * sizeof (uint8_t));
        if(ether_frame == NULL) {
            Utils::print_error(104);
        }
        int status = 0;
        // Listen for incoming ethernet frame from socket sd.
        // Wait for ARP packet with ARP reply
        struct ethhdr *rcv_res = (struct ethhdr *) ether_frame;
        arp_res = (struct arp_header *)(ether_frame + ETH2_HEADER_LEN);
        string dst_mac_string, src_mac_string, src_mac_weird_format_string;
        while(ntohs(rcv_res->h_proto) != PROTO_ARP || ntohs(arp_res->opcode) != ARP_REPLY) {
            if((status = recv(this->arp_rcv_sd, ether_frame, IP_MAXPACKET, 0)) < 0) {
                if(errno == EINTR) {
                    memset(ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
                    continue; // Something weird happened, but let's try again.
                } else if(errno == EAGAIN) {
                    break;
                } else if(ARPScanner::keep_scanning == false && sigint_handled == true) {
                    break;
                } else {
                    Utils::print_error(104);
                }
            }

            char mac_cstring[17];
            // sprintf(mac_cstring, "%02x:%02x:%02x:%02x:%02x:%02x", ether_frame[0], ether_frame[1], ether_frame[2], ether_frame[3], ether_frame[4], ether_frame[5]);
            // dst_mac_string = string(mac_cstring);
            sprintf(mac_cstring, "%02x:%02x:%02x:%02x:%02x:%02x", ether_frame[6], ether_frame[7], ether_frame[8], ether_frame[9], ether_frame[10], ether_frame[11]);
            src_mac_string = string(mac_cstring);
            sprintf(mac_cstring, "%02x%02x.%02x%02x.%02x%02x", ether_frame[6], ether_frame[7], ether_frame[8], ether_frame[9], ether_frame[10], ether_frame[11]);
            src_mac_weird_format_string = string(mac_cstring);
        }

        string my_mac = this->interface.get_mac_string();
        transform(my_mac.begin(), my_mac.end(), my_mac.begin(), ::tolower);
        transform(src_mac_string.begin(), src_mac_string.end(), src_mac_string.begin(), ::tolower);
        if(src_mac_string == my_mac) {
            continue; // ignore replies from this node
        }

        uint32_t sender_ip;
        memcpy(&sender_ip, arp_res->sender_ip, IPV4_LENGTH);
        struct in_addr sender_ip_struct = {
            .s_addr = sender_ip
        };

        // cout << "Received ARP response:" << endl;
        // cout << "Destination MAC (this node): " << dst_mac_string << endl;
        // cout << "Source MAC: " << src_mac_string << endl;
        // // Next is ethernet type code (ETH_P_ARP fo
        // printf("Ethernet type code (2054 = ARP): %u\n", ((ether_frame[12]) << 8) + ether_frame[13]);
        // printf("Ethernet data (ARP header):\n");
        // printf("Hardware type (1 = ethernet (10 Mb)): %u\n", ntohs (arp_res->hardware_type));
        // printf("Protocol type (2048 for IPv4 addresses): %u\n", ntohs (arp_res->protocol_type));
        // printf("Hardware (MAC) address length (bytes): %u\n", arp_res->hardware_len);
        // printf("Protocol (IPv4) address length (bytes): %u\n", arp_res->protocol_len);
        // printf("Opcode (2 = ARP reply): %u\n", ntohs(arp_res->opcode));
        // cout << "Sender protocol (IPv4) address: " << inet_ntoa(sender_ip_struct) << endl;
        // cout << "Sender hardware (MAC) address: ";
        // for(int i=0; i<5; i++) {
        //   printf("%02x:", arp_res->sender_mac[i]);
        // }
        // printf("%02x\n\n", arp_res->sender_mac[5]);

        if(ARPScanner::keep_scanning == true && sigint_handled == false) {
            string sender_ip_string = string(inet_ntoa(sender_ip_struct));
            cout << src_mac_weird_format_string << ": " << sender_ip_string << endl;
            this->xml_data[src_mac_weird_format_string]["ipv4"].insert(sender_ip_string);
        }
    }
}

void ARPScanner::print_out_data() {
    cout << "Generating report...\n";

    this->output_file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << endl;
    this->output_file << "<devices>" << endl;;
    for (auto &host : this->xml_data) {
        this->output_file << "    <host mac=\"" << host.first << "\">" << endl;
        for (auto &addresses : host.second) {
            for(auto &address : addresses.second) {
                this->output_file << "        <" << addresses.first << ">" << address << "</" << addresses.first << ">" << endl;
            }
        }
        this->output_file << "    </host>" << endl;
    }
    this->output_file << "</devices>" << endl;
}

void ARPScanner::ipv6_scan() {
    this->bind_icmpv6();
    for(auto &src : this->interface.get_ipv6_addresses()) {
        this->send_icmpv6_request(src->get_address_string());
    }
}

void ARPScanner::send_icmpv6_request(string src_ipv6_string) {
    char target[INET6_ADDRSTRLEN];
    strcpy(target, "ff02::1");
    unsigned char dst_mac[MAC_LENGTH] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


    struct addrinfo hints, *res;
    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof (hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if (getaddrinfo (target, NULL, &hints, &res) != 0) {
        Utils::print_error(105);
    }
    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) res->ai_addr;
    void *tmp = &(ipv6->sin6_addr);
    char dst_ip[INET6_ADDRSTRLEN];
    if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
        Utils::print_error(105);
    }
    freeaddrinfo (res);


    // Fill out sockaddr_ll.
    struct sockaddr_ll device;
    memset(&device, 0, sizeof (device));
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, this->interface.get_mac_address(), MAC_LENGTH);
    device.sll_halen = 6;
    device.sll_ifindex = this->interface.get_index();

    // ICMP data
    const int datalen = 4;
    uint8_t data[datalen] = {'T', 'E', 'S', 'T'};

    // IPv6 header
    struct ip6_hdr send_iphdr;
    send_iphdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
    send_iphdr.ip6_plen = htons(ICMP_HDRLEN + datalen);
    send_iphdr.ip6_nxt = IPPROTO_ICMPV6;
    send_iphdr.ip6_hops = 255;

    // Source IPv6 address (128 bits)
    if (inet_pton(AF_INET6, src_ipv6_string.c_str(), &(send_iphdr.ip6_src)) != 1) {
        Utils::print_error(105);
    }

    // Destination IPv6 address (128 bits)
    if (inet_pton(AF_INET6, dst_ip, &(send_iphdr.ip6_dst)) != 1) {
        Utils::print_error(105);
    }

    // ICMP header
    struct icmp6_hdr send_icmphdr;
    // Message Type (8 bits): echo request
    send_icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;
    send_icmphdr.icmp6_code = 0;
    send_icmphdr.icmp6_id = htons(1000);
    send_icmphdr.icmp6_seq = htons(0);
    send_icmphdr.icmp6_cksum = 0;
    send_icmphdr.icmp6_cksum = Utils::icmp6_checksum(send_iphdr, send_icmphdr, data, datalen);

    // Fill out ethernet frame header.
    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
    uint8_t *send_ether_frame, *recv_ether_frame;
    send_ether_frame = (uint8_t*)malloc(IP_MAXPACKET);
    if(send_ether_frame == NULL) {
        Utils::print_error(105);
    }
    recv_ether_frame = (uint8_t*)malloc(IP_MAXPACKET);
    if(recv_ether_frame == NULL) {
        Utils::print_error(105);
    }

    const int frame_length = MAC_LENGTH + MAC_LENGTH + 2 + IPV6_HDRLEN + ICMP_HDRLEN + datalen;
    memcpy(send_ether_frame, dst_mac, MAC_LENGTH);
    memcpy(send_ether_frame + 6, this->interface.get_mac_address(), MAC_LENGTH);

    // Next is ethernet type code (ETH_P_IPV6 for IPv6).
    // http://www.iana.org/assignments/ethernet-numbers
    send_ether_frame[12] = ETH_P_IPV6 / 256;
    send_ether_frame[13] = ETH_P_IPV6 % 256;

    // Next is ethernet frame data (IPv6 header + ICMP header + ICMP data).
    // IPv6 header
    memcpy(send_ether_frame + ETH_HDRLEN, &send_iphdr, IPV6_HDRLEN * sizeof (uint8_t));
    // ICMP header
    memcpy(send_ether_frame + ETH_HDRLEN + IPV6_HDRLEN, &send_icmphdr, ICMP_HDRLEN * sizeof (uint8_t));
    // ICMP data
    memcpy(send_ether_frame + ETH_HDRLEN + IPV6_HDRLEN + ICMP_HDRLEN, data, datalen * sizeof (uint8_t));

    // Cast recv_iphdr as pointer to IPv6 header within received ethernet frame.
    struct ip6_hdr *recv_iphdr = (struct ip6_hdr *) (recv_ether_frame + ETH_HDRLEN);
    // Cast recv_icmphdr as pointer to ICMP header within received ethernet frame.
    struct icmp6_hdr *recv_icmphdr = (struct icmp6_hdr *) (recv_ether_frame + ETH_HDRLEN + IPV6_HDRLEN);

    bool done = false;
    int bytes = 0;
    while(ARPScanner::keep_scanning) {
        // Send ethernet frame to socket.
        if ((bytes = sendto(icmpv6_send_sd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
            Utils::print_error(105);
        }

        // receive ethernet frame with ICMP message
        while(ARPScanner::keep_scanning) {
            memset(recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
            if ((bytes = recv(icmpv6_rcv_sd, recv_ether_frame, IP_MAXPACKET, 0)) < 0) {
                if (errno == EAGAIN) {
                    // socket timeout
                    done = true;
                    break;
                } else if (errno == EINTR) {
                    continue; // Something weird happened, but let's try again.
                } else {
                    Utils::print_error(105);
                }
            }


            if(
                (((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IPV6) &&
                (recv_iphdr->ip6_nxt == IPPROTO_ICMPV6) &&
                (recv_icmphdr->icmp6_type == ICMP6_ECHO_REPLY) && (recv_icmphdr->icmp6_code == 0)
            ) {
                char rec_ip[INET6_ADDRSTRLEN];
                // Extract source IP address from received ethernet frame.
                if (inet_ntop(AF_INET6, &(recv_iphdr->ip6_src), rec_ip, INET6_ADDRSTRLEN) == NULL) {
                    Utils::print_error(105);
                }


                char mac_cstring[17];
                sprintf(mac_cstring, "%02x%02x.%02x%02x.%02x%02x", recv_ether_frame[6], recv_ether_frame[7], recv_ether_frame[8], recv_ether_frame[9], recv_ether_frame[10], recv_ether_frame[11]);
                string src_mac_weird_format_string = string(mac_cstring);
                string sender_ip_string = string(rec_ip);

                done = true;
                cout << src_mac_weird_format_string << ": " << sender_ip_string << endl;
                this->xml_data[src_mac_weird_format_string]["ipv6"].insert(sender_ip_string);
            }
        }


        if (done) {
            break;
        }
    }

    free(send_ether_frame);
    free(recv_ether_frame);

    // Close socket descriptors.
    if(icmpv6_send_sd > 0) {
        close(icmpv6_send_sd);
    }
    if(icmpv6_rcv_sd > 0) {
        close(icmpv6_rcv_sd);
    }
}
