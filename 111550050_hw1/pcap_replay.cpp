#include <arpa/inet.h> // inet_addr7
#include <cstring>     // memcpy
#include <iostream>
#include <netinet/ether.h> // ethernet header struct
#include <netinet/ip.h>    // ip header struct
#include <netinet/udp.h>   // udp header struct
#include <pcap.h>          // pcap libary
#include <unistd.h>

#define MAX_PACKET_SIZE 65535

/* some useful identifiers:
 * - ETH_ALEN = 6   (ethernet address length)
 * - ETH_HLEN = 14	(ethernet header length)
*/

// DONE 5
void modify_mac_address(struct ether_header *eth_header) {
    // struct ether_header reference:
    // https://sites.uclouvain.be/SystInfo/usr/include/net/ethernet.h.html
    eth_header->ether_shost[0] = 0x08;
    eth_header->ether_shost[1] = 0x00;
    eth_header->ether_shost[2] = 0x12;
    eth_header->ether_shost[3] = 0x34;
    eth_header->ether_shost[4] = 0x56;
    eth_header->ether_shost[5] = 0x78;
    
    eth_header->ether_dhost[0] = 0x08;
    eth_header->ether_dhost[1] = 0x00;
    eth_header->ether_dhost[2] = 0x12;
    eth_header->ether_dhost[3] = 0x34;
    eth_header->ether_dhost[4] = 0xac;
    eth_header->ether_dhost[5] = 0xc2;
}

// DONE 6
void modify_ip_address(struct ip *ip_header) {
    ip_header->ip_src.s_addr = htonl(0x0A010103);
    ip_header->ip_dst.s_addr = htonl(0x0A010104);
}

int main() {
    char errmsg[PCAP_ERRBUF_SIZE];

    // DONE 1: Open the pcap file
    const char* PCAP_SAVEFILE_PATH = "test.pcap";
    pcap_t* savefile = pcap_open_offline(PCAP_SAVEFILE_PATH, errmsg);
    if(!savefile) {
        fprintf(stderr, "Failed to open savefile: %s\n", errmsg);
        exit(1);
    }
    
    // DONE 2: Open session with loopback interface "lo"
    pcap_t* lo = pcap_create("lo", errmsg);
    if(!lo) {
        fprintf(stderr, "Failed to create session with lo: %s\n", errmsg);
        exit(1);
    }
    if(pcap_activate(lo) < 0) {
        pcap_perror(lo, "Failed to activate session with lo: ");
        exit(1);
    }

    
    struct pcap_pkthdr *header;
    const u_char *packet;

    // DONE 8: Variables to store the time difference between each packet
    timeval prevTime;
    long second, microsecond;
    short first = 0;

    // DONE 3: Loop through each packet in the pcap file
    while(pcap_next_ex(savefile, &header, &packet) != PCAP_ERROR_BREAK) {
        //TODO 3.5: Detect PCAP_ERROR

        // DONE 4: Send the original packet
        if(pcap_sendpacket(lo, packet, header->caplen) != 0) {
            pcap_perror(lo, "Failed to send original packet: ");
        }

        // DONE 5: Modify mac address (function up above)
        struct ether_header *eth_header = (struct ether_header *)packet;
        modify_mac_address(eth_header);

        // DONE 6: Modify ip address if it is a IP packet (hint: ether_type)
        if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            // Assuming Ethernet headers
            struct ip *ip_header = (struct ip *)(packet + ETH_HLEN);
            modify_ip_address(ip_header);   // modify function up above
        }

        // DONE 8: Calculate the time difference between the current and the
        // previous packet and sleep. (hint: usleep)
        second = (header->ts.tv_sec - prevTime.tv_sec) * first;
        microsecond = (header->ts.tv_usec - prevTime.tv_usec) * first;
        first = 1;
        if(microsecond < 0) {
            microsecond += 1e6;
            second--;
        }

        sleep(second);
        usleep(microsecond);

        // DONE 7: Send the modified packet
        if(pcap_sendpacket(lo, packet, header->caplen) != 0) {
            pcap_perror(lo, "Failed to send modified packet: ");
        }

        // DONE 8: Update the previous packet time
        prevTime = header->ts;
    }
    
    // Close the pcap file
    pcap_close(savefile);
    pcap_close(lo);
    
    return 0;
}