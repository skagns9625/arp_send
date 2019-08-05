#ifndef SHEADER_H
#define SHEADER_H
#include <pcap.h>
#include <netinet/ip.h>
#include <string.h>

#define ETH_LEN 6
#define ETHERTYPE_ARP 0x0806
#define ETHTYPE 0x0001
#define PROTOTYPE_IP 0x0800
#define REQUEST 0x0001

typedef struct{
    u_char dst[ETH_LEN];
    u_char src[ETH_LEN];
    u_short type;

}eth_hdr;
#define SIZE_ETH (sizeof(eth_hdr))


typedef struct{
    uint16_t Htype;
    uint16_t Ptype;

    uint8_t H_add_len;
    uint8_t P_add_len;

    uint16_t Opcode;

    u_char Smac[6];
    uint8_t SIP[4];

    u_char Tmac[6];
    u_char TIP[4];
}arp_hdr;
#define SIZE_ARP (sizeof(arp_hdr))

#endif // SHEADER_H
