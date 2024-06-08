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
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define ETHER_PACKET_LEN 14
#define FORWARD 0
#define BACKWARD 1

#define BLOCK_PACKET_HEADER_LEN 54

void tcp_block(const unsigned char* packet, uint32_t p_len, int type, char* block_data);
bool check_block(int type, char* block_data, const unsigned char* payload, int payload_len);
void blocking(unsigned char* packet, uint32_t p_len);
void make_packet(unsigned char* block_packet, unsigned char* org_packet, int type, uint32_t p_len);
void send_forward(const unsigned char* packet);
void send_backward(const unsigned char* packet);

uint8_t my_mac[6];
const char* backward_tcpdata = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
int backward_datalen;

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

    // get self mac address
    int sockfd = socket(Af_INET, SOCK_DGRAM, 0);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, param._dev, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Fail to get MAC address\n");
        return -1;
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    // 
    backward_datalen = strlen(backward_tcpdata);

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
                blocking(packet);
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

void blocking(unsigned char* packet, uint32_t p_len) {
    unsigned char forward_packet[100];
    unsigned char backward_packet[100];

    make_packet(forward_packet, packet, FORWARD);
    make_packet(backward_packet, packet, BACKWARD);

    send_forward(forward_packet);
    send_backward(backward_packet);
}

void make_packet(unsigned char* block_packet, unsigned char* org_packet, int type, uint32_t p_len) {
    if (p_len > 100) {
        p_len = 100;
    }
    memcpy(block_packet, org_packet, p_len);
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr* tcp_header;

    // ethernet
    eth_header = (struct ether_header*)block_packet;
    if (type == BACKWARD) {
        for (int i = 0; i < 6; i++) {
            eth_header.ether_dhost[i] = eth_header.ether_shost[i];
        }
    }
    for (int i = 0; i < 6; i++) {
        eth_header.ether_shost[i] = my_mac[i];
    }

    // ip
    ip_header = (struct ip*)(block_packet + ETHER_PACKET_LEN);
    ip_header->ip_len = 54;
    if (type == BACKWARD) {
        ip_header->ip_len += backward_datalen;
        ip_header->ip_ttl = 128;
        uint32_t tmp;
        tmp = ip_header->ip_src;
        ip_header->ip_src = ip_header->ip_dst;
        ip_header->ip_dst = tmp;
    }

    // tcp
    tcpheader = (struct tcphdr*)(ip_header + (ip_header->ip_hl * 4));
    unsigned char* tcp_data = (unsigned char*)(tcpheader + (tcpheader->th_off *4));
    tcpheader->th_seq += strlen(tcp_data);
    tcpheader->th_off = 20;
    if (type == BACKWARD) {
        uint16_t tmp;
        tmp = tcpheader->th_sport;
        tcpheader->th_sport = tcpheader->th_dport;
        tcpheader->th_dport = tmp;
        tcpheader->th_flag = TH_FIN | TH_ACK;
    }
    else if (type == FORWARD) {
        tcpheader->th_flag = TH_RST | TH_ACK;
    }
    unsigned char* new_tcp_data = (unsigned char*)(tcpheader + (tcpheader->th_off * 4));
    if (type == BACKWARD) {
        strcpy(new_tcp_data, backward_tcpdata);
    }
}

void send_forward(const unsigned char* packet) {
    
}

void send_backward(const unsigned char* packet) {

}