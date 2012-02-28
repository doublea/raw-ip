#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <errno.h>

struct ip_packet {
    uint8_t hdr_info;
    uint8_t diffserv_ecn;
    uint16_t total_len;
    uint16_t ident;
    uint16_t frag_info;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t src;
    uint32_t dst;
    char optsndata[];
};

// From RFC 1071
uint16_t ip_csum(void *packet, int len) {
    uint16_t *p = (uint16_t*)packet;
    uint32_t sum = 0;
    for (;len > 1; sum += *p++, len -=2);
    if (len > 0)
        sum += *(uint8_t*)p;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

int main(void) {
    int sock, ifindex;
    struct ifreq if_info;
    struct sockaddr_ll addr;
    socklen_t addr_len;
    char ifname[] = "lo";
    char hwaddr[] = {0xde, 0xad, 0xca, 0xfe, 0xba, 0xbe };
    struct ip_packet ip;
    char msg[] = "Hello World!";

    if ((sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_802_3))) == -1) {
        perror("Error creating AF_PACKET socket.");
        exit(EXIT_FAILURE);
    }

    // Find ifindex for eth0
    memset(&if_info, 0, sizeof(struct ifreq));
    memcpy(&if_info.ifr_name, ifname, sizeof(ifname));
    if (ioctl(sock, SIOCGIFINDEX, &if_info) == -1) {
        perror("Error getting eth0 interface index.");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(struct sockaddr_ll));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    memcpy(&addr.sll_addr, hwaddr, sizeof(hwaddr));
    addr.sll_halen = 6;
    addr.sll_ifindex = if_info.ifr_ifindex;

    memset(&ip, 0, sizeof(ip));
    ip.hdr_info = 0x45; // IPv4, 32*5 = 20 bytes header
    ip.total_len = htons(20+sizeof(msg));
    ip.ttl = 0xFF;
    ip.proto = 0xFD; // For experimentation and testing (See RFC 3692)
    ip.src = htonl(0x7F000001); // 127.0.0.1
    ip.dst = htonl(0x7F000001); 
    memcpy(&ip.optsndata, msg, sizeof(msg));
    ip.csum = ip_csum((uint16_t*)&ip, (ip.hdr_info & 0xF) << 2);

    if (sendto(sock, &ip, sizeof(ip)+sizeof(msg), 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) == -1) {
        perror("Error sending packet.");
        exit(EXIT_FAILURE);
    }

    return 0;
}
