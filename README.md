# tcp-block

Pattern으로 Host만을 받습니다. 

![Untitled](tcp-block%20527a3bc773454a98b597311be6549219/Untitled.png)

실행한 뒤 browser에서 gilgil.net에 접속하면 이렇게 여러 번 target packet을 감지하는 것을 확인할 수 있습니다.

![Untitled](tcp-block%20527a3bc773454a98b597311be6549219/Untitled%201.png)

warning.or.kr으로 리디렉션은 되지 않고 이렇게 연결에 실패한 것만 확인할 수 있습니다.

원인 분석을 해보니

![Untitled](tcp-block%20527a3bc773454a98b597311be6549219/Untitled%202.png)

FORWARD 패킷만 잔뜩 잡히고, BACKWARD 패킷은 잡히지 않았습니다.

서버는 RST 패킷을 받아서 연결을 종료했지만, BACKWARD 패킷이 가지 않아 서버에게 계속해서 접속 요청을 보내는 것으로 생각됩니다.

그리고 그 요청을 보낼 때마다 다시 RST FORWARD 패킷을 보내서 계속 연결이 지연되다가 결국 연결에 실패한 것으로 보여집니다.

아래는 raw socket을 이용하여 패킷을 보내는 코드입니다.

```c
int main(int argc, char* argv[]) {
		...
		(생략)
		...
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
    ...
    (생략)
    ...
}

void send_packet(const unsigned char* packet, uint32_t send_len) {
    memcpy(sock_buffer, packet, send_len);

    if (sendto(sd, sock_buffer, send_len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "send fail\n");
    }
}
```

어느 부분이 잘못 되었는 지를 못 찾아서.. 여기서 마무리하게 되었습니다.