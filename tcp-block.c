#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>

#define ETHER_PACKET_LEN 14

void tcp_block(const unsigned char* packet, uint32_t p_len, int type, char* block_data);
bool check_block(int type, char* block_data, const unsigned char* payload, int payload_len);

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

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param._dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param._dev, errbuf);
        return -1;
    }

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

        // HTTP 인지 확인 (TCP 80번 포트)
        if (ntohs(tcp_header->th_dport) == 80 && payload_len > 0) {
            if (check_block(type, block_data, payload, payload_len)) {
                printf("Target detected\n");
                //blocking(packet);
            }
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

void blocking(unsigned char* packet) {

}