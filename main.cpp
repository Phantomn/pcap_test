#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

struct ethernet{
        uint8_t descMac[6];
        uint8_t srcMac[6];
        uint16_t ethType;
};
struct ip{
        uint8_t version;
        uint8_t hdrLen;
        uint8_t dscp;
        uint16_t totLen;
        uint16_t ID;
        uint16_t flags;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t chksum;
        uint8_t srcIp[4];
        uint8_t destIp[4];
};
struct tcp{
        uint16_t srcPort;
        uint16_t destPort;
        uint32_t seqNum;
        uint8_t hdrLen;
        uint8_t flags[12];
        uint16_t winSize;
        uint16_t chksum;
        uint16_t urgPtr;
};
struct udp{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t len;
    uint16_t chkSum;
    uint8_t data[100];
};

struct http{
        uint8_t string[100];
};
struct ethernet eth;
struct ip ip;
struct tcp tcp;
struct udp udp;
struct http http;
void eth_print(const u_char* ptr){
        memcpy(eth.descMac,ptr,6);
        memcpy(eth.srcMac,ptr=ptr+6,6);
        eth.ethType = *(ptr=ptr+6) << 8 | *(ptr=ptr+1);
        printf("Dest \tMac : \t");
        for(int i=0;i<6;i++){
            if(i<5)
                printf("%02x:",eth.descMac[i]);
            else
                printf("%02x\n",eth.descMac[i]);
        }
        printf("Source \tMac : \t");
        for(int i=0;i<6;i++){
            if(i<5)
                printf("%02x:",eth.srcMac[i]);
            else
                printf("%02x\n",eth.srcMac[i]);
        }
        if(eth.ethType == 0x0800)
            printf("Type : IPv4\n");
        /*else if(eth.ethType == 0x0806)
            printf("Type : ARP\n");
        else if(eth.ethType == 0x0835)
            printf("Type : RARP\n");
        else if(eth.ethType == 0x86DD)
            printf("Protocol : IPv6\n");*/
}
void ip_print(const u_char* ptr){
    u_char val_v_len = *ptr;
    ip.version = (val_v_len & 0xF0)>>4;
    ip.hdrLen = (val_v_len & 0x0F)*4;
    uint8_t val_dscp = *(ptr=ptr+1);
    uint8_t DSCP[2];
    DSCP[0] = (val_dscp & 0xFC);
    DSCP[1] = (val_dscp & 0x3);
    ip.totLen = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.ID = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.flags = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.ttl = *(ptr=ptr+1);
    ip.protocol = *(ptr=ptr+1);
    ip.chksum = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    memcpy(ip.srcIp, ptr=ptr+1, 4);
    memcpy(ip.destIp, ptr=ptr+4, 4);


    if(ip.version == 4)
        printf("Version : IPv4\n");
    else if(ip.version == 6)
        printf("Version : IPv6\n");

    //printf("Identification : 0x%04x\n", ip.ID);
    //printf("Flags 0x%04x\n",ip.flags);
    //printf("Time to live : %d\n",ip.ttl);
    //if(ip.protocol == 0x01)
    //    printf("Protocol : ICMP\n");
    if(ip.protocol == 0x06){
        printf("Protocol : TCP\n");
        printf("Header Length : %d\n",ip.hdrLen);
        printf("Total Length : %d\n",ip.totLen);
        printf("Source IP : %d.%d.%d.%d\n",ip.srcIp[0],ip.srcIp[1],ip.srcIp[2],ip.srcIp[3]);
        printf("Destination IP : %d.%d.%d.%d\n",ip.destIp[0],ip.destIp[1],ip.destIp[2],ip.destIp[3]);
    }else if(ip.protocol == 0x11)
        printf("Protocol : UDP\n");
    else if(ip.protocol == 0x29)
        printf("Protocol : IPv6\n");
    //printf("CheckSum : 0x%04x\n", ip.chksum);
}
void tcp_print(const u_char* ptr){
    tcp.srcPort = *(ptr) << 8 | *(ptr=ptr+1);
    tcp.destPort = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    if(tcp.destPort == 80){
        printf("Source Port : %d\n", tcp.srcPort);
        printf("Destination Port : %d\n", tcp.destPort);
        tcp.hdrLen = (*(ptr=ptr+9) >> 4)*4;
        printf("Header Length : %d\n",tcp.hdrLen);
    }else if(tcp.destPort == 443){
        printf("Source Port : %d\n", tcp.srcPort);
        printf("Destination Port : %d\n", tcp.destPort);
        tcp.hdrLen = (*(ptr=ptr+9) >> 4)*4;
        printf("Header Length : %d\n",tcp.hdrLen);
    }
}
void udp_print(const u_char* ptr){
    udp.srcPort = *(ptr) << 8 | *(ptr=ptr+1);
    udp.destPort = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    if(udp.destPort == 80){
        printf("Source Port : %d\n", udp.srcPort);
        printf("Destination Port : %d\n", udp.destPort);
        udp.len = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
        printf("Length : %d\n",udp.len);
        memcpy(udp.data,ptr=ptr+3, udp.len-8);
        printf("Data : %s\n",udp.data);
    }

}
void http_print(const u_char* ptr){
    printf("HTTP Data : ");
    for(int i=0;i<10;i++){
        if(0x20 <= *ptr+i || *ptr+i <= 0x80)
            printf("%c", *(ptr+i));
        else
            continue;
        if(*ptr+i=='\x0d' && *(ptr+i+1) =='\x0a')
            break;
    }
    printf("\n");
}
void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
			usage();
			return -1;
	}

	char* dev = argv[1]; 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
			fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
			return -1;
	}

    while (true) {
        const u_char* packet;
        struct pcap_pkthdr* header;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("===================================\n");
        printf("%u bytes captured\n", header->caplen);
        printf("==============Ethernet=============\n");
        eth_print(packet);
        if(eth.ethType == 0x0800){

            printf("=========Internet Protocol=========\n");
            ip_print(&packet[sizeof(eth)]);
            if(ip.protocol == 0x06){
                tcp_print(&packet[sizeof(eth)+ip.hdrLen]);
                if(tcp.destPort == 80){
                //printf("size eth : %d, ip_size : %d, tcp_size : %d\n",sizeof(eth),ip.hdrLen,tcp.hdrLen);
                    http_print(&packet[sizeof(eth)+ip.hdrLen+tcp.hdrLen]);
                }
            }else if(ip.protocol == 0x11){
                udp_print(&packet[sizeof(eth)+ip.hdrLen]);
            }
        }

        printf("===================================\n");
    }

	pcap_close(handle);
	return 0;
}
