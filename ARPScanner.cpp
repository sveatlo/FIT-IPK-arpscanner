#include <arpa/inet.h>
#include <bitset>
#include <iostream>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sstream>
#include "ARPScanner.h"
#include "Utils.h"

using namespace std;

typedef struct _arp_packet
{
	struct ether_header ether;      // Ethernet Header
	struct arphdr arp;              // ARP Header

	uint8_t  sender_mac[ETH_ALEN];
	uint32_t sender_ip;
	uint8_t  target_mac[ETH_ALEN];
	uint32_t target_ip;

	uint8_t  padding[18];           // Paddign
} arp_packet;

char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (char*)(tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (uint8_t*)(tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}


ARPScanner::ARPScanner(string __interface, string __output_file) {;
    this->interface = __interface;
    this->output_file.open(__output_file, ios::out | ios::trunc);

    if(!this->output_file) {
        Utils::print_error(2);
    }

    this->ipv4_scan();
}

void ARPScanner::ipv4_scan() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) {
        Utils:: print_error(101);
    }
    struct ifreq conf;

    // get ipv4 netmask
    memset(&conf, 0, sizeof(conf)); // fill confs with zero's
    strncpy(conf.ifr_name, this->interface.c_str(), IFNAMSIZ - 1);
    conf.ifr_addr.sa_family = AF_INET; //ipv4
    if (ioctl(s, SIOCGIFNETMASK, &conf) < 0) {
        Utils::print_error(101);
    }
    char* netmask_array = (conf.ifr_netmask.sa_data) + 2;
    char cnetmask[33];
    sprintf(cnetmask, "%d.%d.%d.%d", (unsigned char)netmask_array[0], (unsigned char)netmask_array[1], (unsigned char)netmask_array[2], (unsigned char)netmask_array[3]);

    //get ipv4 address
    memset(&conf, 0, sizeof(conf)); // fill confs with zero's
    strncpy(conf.ifr_name, this->interface.c_str(), IFNAMSIZ - 1);
    conf.ifr_addr.sa_family = AF_INET; //ipv4
    if (ioctl(s, SIOCGIFADDR, &conf) < 0) {
        Utils::print_error(101);
    }
    char* cipv4_addr = inet_ntoa(((struct sockaddr_in *)&conf.ifr_addr)->sin_addr);

    //get interface HW address
    memset(&conf, 0, sizeof(conf)); // fill confs with zero's
    strncpy(conf.ifr_name, this->interface.c_str(), IFNAMSIZ - 1);
    conf.ifr_addr.sa_family = AF_INET; //ipv4
    if (ioctl(s, SIOCGIFHWADDR, &conf) < 0) {
        Utils::print_error(101);
    }
    this->src_mac = allocate_ustrmem(6);
    memcpy(this->src_mac, conf.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    // Report source MAC address to stdout.
    printf ("MAC address for interface %s is ", this->interface.c_str());
    for (int i=0; i<5; i++) {
        printf ("%02x:", this->src_mac[i]);
    }
    printf ("%02x\n", this->src_mac[5]);

    struct sockaddr_ll device;
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (this->interface.c_str())) == 0) {
        Utils::print_error(101);
    }
    printf ("Index for interface %s is %i\n", this->interface.c_str(), device.sll_ifindex);
    this->if_index = device.sll_ifindex;

    close(s);

    uint32_t mask_addr = Utils::ip_to_int(string(cnetmask));
    this->ipv4_address = Utils::ip_to_int(string(cipv4_addr));
    uint32_t net_lower = (this->ipv4_address & mask_addr) + 1;
    uint32_t net_upper = (net_lower | (~mask_addr)) - 1;


    cout << "IPv4 addr: \t" << bitset<32>(this->ipv4_address) << endl;
    cout << "Netmask: \t" << bitset<32>(mask_addr) << endl;
    cout << "First address: \t" << bitset<32>(net_lower) << endl;
    cout << "Last address: \t" << bitset<32>(net_upper) << endl;

    cout << "IPv4 addr: \t" << Utils::int_to_ip(this->ipv4_address) << endl;
    cout << "Netmask: \t" << Utils::int_to_ip(mask_addr) << endl;
    cout << "First address: \t" << Utils::int_to_ip(net_lower) << endl;
    cout << "Last address: \t" << Utils::int_to_ip(net_upper) << endl;

    for(uint32_t addr = net_lower; addr <= net_upper; addr++) {
        this->send_arp_request(addr);
    }
}

void ARPScanner::send_arp_request(uint32_t ipv4_remote_address) {
	// Socket to send ARP packet
	int arp_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if( arp_fd == -1 ) {
        Utils::print_error(102);
	}

	arp_packet pkt;
	memset(pkt.ether.ether_dhost, 0xFF, sizeof(pkt.ether.ether_dhost));
	memcpy(pkt.ether.ether_shost, this->src_mac, sizeof(pkt.ether.ether_dhost));
	pkt.ether.ether_type = htons(ETHERTYPE_ARP);

	pkt.arp.ar_hrd = htons(ARPHRD_ETHER);
	pkt.arp.ar_pro = htons(ETHERTYPE_IP);
	pkt.arp.ar_hln = ETHER_ADDR_LEN;
	pkt.arp.ar_pln = sizeof(pkt.sender_ip);
	pkt.arp.ar_op = htons(ARPOP_REQUEST);

	memcpy(pkt.sender_mac, this->src_mac, sizeof(pkt.sender_mac));
	pkt.sender_ip = htonl(this->ipv4_address);
	memset(pkt.target_mac, 0 , sizeof(pkt.target_mac));
    char addr[] = {(unsigned char)(ipv4_remote_address >> 24), (unsigned char)(Utils::rotr(ipv4_remote_address, 24) >> 24), (unsigned char)(Utils::rotr(ipv4_remote_address, 16) >> 24), (unsigned char)(Utils::rotr(ipv4_remote_address, 8) >> 24)};
	pkt.target_ip = inet_addr(addr);

	memset(pkt.padding, 0 , sizeof(pkt.padding));


	struct sockaddr_ll sa;
	sa.sll_family   = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_ifindex  = this->if_index;
	sa.sll_hatype   = ARPHRD_ETHER;
	sa.sll_pkttype  = PACKET_BROADCAST;
	sa.sll_halen    = 0;
	// sa.sll_addr not set


	int retVal = sendto(arp_fd, &pkt, sizeof(pkt), 0,(struct sockaddr *)&sa, sizeof(sa));
	if(retVal < 0) {
		Utils::print_error(102);
	}

	close(arp_fd);
}
