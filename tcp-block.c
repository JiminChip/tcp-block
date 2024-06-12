#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_packet.h>

#define ETHER_PACKET_LEN 14
#define FORWARD 0
#define BACKWARD 1

#define BLOCK_PACKET_HEADER_LEN 54

void tcp_block(const unsigned char* packet, uint32_t p_len, int type, char* block_data);
bool check_block(int type, char* block_data, const unsigned char* payload, int payload_len);
void blocking(const unsigned char* packet, uint32_t p_len);
void make_packet(unsigned char* block_packet, const unsigned char* org_packet, int type, uint32_t p_len);
void send_packet(const unsigned char* packet, uint32_t send_len);
unsigned short checksum(void *b, int len);

struct pseudo_header {
    struct in_addr source_addr;
    struct in_addr dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint8_t my_mac[6];
const char* backward_tcpdata = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
int backward_datalen;

int sd;
char sock_buffer[1514];
struct ifreq ifr_;
struct sockaddr_ll sa;

void usage() {
    printf("[SNS] TCP Block Usage\n");
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

typedef struct command_line_parameter{
    char* _dev;
    int type;
    char* _data;
} Param;

bool command_line_parser(Param* param, int argc, char* argv[]) {
    if (argc != 3) {
        return false;
    }
    param->_dev = (char*)malloc(sizeof(char) * strlen(argv[1]));
    strcpy(param->_dev, argv[1]);

    if (!strncmp(argv[2], "Host: ", 6)) {
        param->type = 0;
        param->_data = (char*)malloc(sizeof(char) * strlen(&argv[2][6]));
        strcpy(param->_data, &argv[2][6]);
    }
    else {
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    Param param;

    // parse command-line parameter
    if (!command_line_parser(&param, argc, argv)) {
        usage();
        return -1;
    }

    // 
    backward_datalen = strlen(backward_tcpdata);

    // make raw socket
    sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        fprintf(stderr, "Fail to make socket\n");
        return -1;
    }

    memset(&ifr_, 0, sizeof(ifr_));
    strncpy(ifr_.ifr_name, param._dev, IFNAMSIZ - 1);
    if (ioctl(sd, SIOCGIFINDEX, &ifr_) == -1) {
        fprintf(stderr, "set network interface fail\n");
        close(sd);
        return -1;
    }
    sa.sll_ifindex = ifr_.ifr_ifindex;
    sa.sll_halen = ETH_ALEN;

    // get self mac address
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, param._dev, IFNAMSIZ - 1);

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Fail to get MAC address\n");
        return -1;
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    // open pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param._dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param._dev, errbuf);
        return -1;
    }

    // capture packet & block
    while (true) {
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        
        tcp_block(packet, header->caplen, param.type, param._data);
    }
    close(sd);
    free(param._data);
    free(param._dev);

    return 0;
}

void tcp_block(const unsigned char* packet, uint32_t p_len, int type, char* block_data) {
    struct ip* ip_header;
    struct tcphdr* tcp_header;
    int ip_header_len;
    int tcp_header_len;
    const unsigned char* payload;
    int payload_len;

    // parse packet
    // ip 시작 위치
    ip_header = (struct ip*)(packet + ETHER_PACKET_LEN);
    ip_header_len = ip_header->ip_hl * 4;

    // tcp 프로토콜 확인
    if (ip_header->ip_p == IPPROTO_TCP) {
        // TCP 헤더 위치
        tcp_header = (struct tcphdr*)(packet + ETHER_PACKET_LEN + ip_header_len);
        tcp_header_len = tcp_header->th_off * 4;

        payload = (unsigned char*)(packet + ETHER_PACKET_LEN + ip_header_len + tcp_header_len);
        payload_len = ntohs(ip_header->ip_len) - (ip_header_len + tcp_header_len);

        // HTTP 인지 확인 (TCP 80번 포트) & HTTPS 인지 확인 (TCP 443번 포트)
        if (ntohs(tcp_header->th_dport) == 80 && payload_len > 0) {
            if (check_block(type, block_data, payload, payload_len)) {
                printf("Target detected\n");
                blocking(packet, p_len);
            }
        }
        else if (ntohs(tcp_header->th_dport) == 443 && payload_len >0) {
            
        }
    }
}

bool check_block(int type, char* block_data, const unsigned char* payload, int payload_len) {
    // target host를 block
    if (type == 0) {
        for (int i = 0; i < payload_len - 6; i++) {
            if (!strncmp("Host: ", &payload[i], 6) && !strncmp(&payload[i+6], block_data, strlen(block_data))) {
                return true;
            }
        }
    }
    return false;
}

void blocking(const unsigned char* packet, uint32_t p_len) {
    unsigned char forward_packet[200];
    unsigned char backward_packet[200];

    make_packet(forward_packet, packet, FORWARD, p_len);
    make_packet(backward_packet, packet, BACKWARD, p_len);

    send_packet(backward_packet, BLOCK_PACKET_HEADER_LEN + backward_datalen);
    send_packet(forward_packet, BLOCK_PACKET_HEADER_LEN);
    
}

void make_packet(unsigned char* block_packet, const unsigned char* org_packet, int type, uint32_t p_len) {
    if (p_len > 200) {
        p_len = 200;
    }
    memset(block_packet, 0, 200);
    struct ether_header *eth_header;
    struct ether_header *org_eth_header;
    struct ip *ip_header;
    struct ip *org_ip_header;
    struct tcphdr* tcp_header;
    struct tcphdr* org_tcp_header;

    // ethernet
    eth_header = (struct ether_header*)block_packet;
    org_eth_header = (struct ether_header*)org_packet;
    if (type == BACKWARD) {
        for (int i = 0; i < 6; i++) {
            eth_header->ether_dhost[i] = org_eth_header->ether_shost[i];
        }
    }
    else if (type == FORWARD) {
        for (int i = 0; i < 6; i++) {
            eth_header->ether_dhost[i] = org_eth_header->ether_dhost[i];
        }
    }
    for (int i = 0; i < 6; i++) {
        eth_header->ether_shost[i] = my_mac[i];
    }
    eth_header->ether_type = 0x0008;

    // ip
    ip_header = (struct ip*)(block_packet + ETHER_PACKET_LEN);
    org_ip_header = (struct ip*)(org_packet + ETHER_PACKET_LEN);
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_id = org_ip_header->ip_id;
    ip_header->ip_off = org_ip_header->ip_off;
    if (type == BACKWARD) {
        ip_header->ip_len = ntohs(40 + backward_datalen);
        ip_header->ip_ttl = 128;
        ip_header->ip_src = org_ip_header->ip_dst;
        ip_header->ip_dst = org_ip_header->ip_src;
    }
    else if (type == FORWARD) {
        ip_header->ip_len = ntohs(40);
        ip_header->ip_ttl = org_ip_header->ip_ttl;
        ip_header->ip_src = org_ip_header->ip_src;
        ip_header->ip_dst = org_ip_header->ip_dst;
    }
    ip_header->ip_p = 0x06;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = checksum((unsigned short*)ip_header, sizeof(struct ip));

    // tcp
    tcp_header = (struct tcphdr*)((uint8_t*)ip_header + 20);
    org_tcp_header = (struct tcphdr*)((uint8_t*)org_ip_header + (org_ip_header->ip_hl * 4));
    unsigned char* tcp_data = (unsigned char*)((uint8_t*)org_tcp_header + (org_tcp_header->th_off * 4));
    
    tcp_header->th_off = 5;
    tcp_header->th_x2 = org_tcp_header->th_x2;
    if (type == BACKWARD) {
        tcp_header->th_seq = org_tcp_header->th_ack;
        tcp_header->th_ack = htonl(ntohl(org_tcp_header->th_seq) + strlen(tcp_data));
        printf("back: %ld\n", strlen(tcp_data));
        tcp_header->th_dport = org_tcp_header->th_sport;
        tcp_header->th_sport = org_tcp_header->th_dport;
        tcp_header->th_flags = TH_FIN | TH_ACK;
    }
    else if (type == FORWARD) {
        tcp_header->th_ack = org_tcp_header->th_ack;
        tcp_header->th_seq = htonl(ntohl(org_tcp_header->th_seq) + strlen(tcp_data));
        printf("for: %ld\n", strlen(tcp_data));
        tcp_header->th_dport = org_tcp_header->th_dport;
        tcp_header->th_sport = org_tcp_header->th_sport;
        tcp_header->th_flags = TH_RST | TH_ACK;
    }
    tcp_header->th_win = org_tcp_header->th_win;
    tcp_header->th_urp = 0;
    unsigned char* new_tcp_data = (unsigned char*)((uint8_t*)tcp_header + (tcp_header->th_off * 4));
    if (type == BACKWARD) {
        memcpy(new_tcp_data, backward_tcpdata, 57);
    }
    struct pseudo_header pseudo_hdr;
    pseudo_hdr.source_addr = ip_header->ip_src;
    pseudo_hdr.dest_addr = ip_header->ip_dst;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    int total_len;
    if (type == BACKWARD)
        total_len = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + backward_datalen;
    else
        total_len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    uint8_t* buf = (uint8_t*)malloc(total_len);
    pseudo_hdr.tcp_length = htons(total_len - sizeof(struct pseudo_header));
    memcpy(buf, &pseudo_hdr, sizeof(struct pseudo_header));
    if (type == BACKWARD)
        memcpy(buf + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr) + backward_datalen);
    else
        memcpy(buf + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr));
    tcp_header->th_sum = checksum(buf, total_len);
    
    
}

void send_packet(const unsigned char* packet, uint32_t send_len) {
    memcpy(sock_buffer, packet, send_len);

    if (sendto(sd, sock_buffer, send_len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "send fail\n");
    }
}

unsigned short checksum(void *b, int len) {
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char* )buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}