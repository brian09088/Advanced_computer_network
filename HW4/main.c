#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

unsigned short checksum(unsigned short *buffer, int buffersz){
    unsigned long sum = 0xffff;

    while(buffersz > 1){
        sum += *buffer;
        buffer++;
        buffersz -= 2;
    }

    if(buffersz == 1)
        sum += *(unsigned char*)buffer;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

void print_usage(){
    printf("%s\n", "This program is aimed to trace router via ICMP");
    printf("%s\n", "################");
    printf("%s\n", "Command Line Format:");
    printf("%s\n", "1. ./prog -h");
    printf("%s\n", "2. prog <hop-distance> <destiantion_ip_address>");
}

int main(int argc, char **argv){
    struct sockaddr_in IP_send_header; //發送的IP header
    struct iphdr *IP_recv_header; //接收的IP header
    struct icmphdr ICMP_send_header; //發送的ICMP header
    struct icmphdr *ICMP_recv_header; //接收的ICMP header
    struct sockaddr_in received_IP; //接收到的IP

    int network_number;
    int soc_send, soc_recv;
    char buffer[1024];
    int TTL;
    int max_hopping;

    //determine the login identity
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}

    // 將使用者輸入的 IP 轉成 network order
    network_number = inet_pton(PF_INET, argv[2], &IP_send_header.sin_addr);
    if(network_number < 0){
        perror("inet_pton");
        exit(-1);
    }

    //send socket
    soc_send = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(soc_send < 0){
        perror("socket");
        exit(-1);
    }

    //receive socket
    soc_recv = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(soc_recv < 0){
        perror("socket");
        exit(-1);
    }

    //enter point
    if(argc == 2 || argc == 3){
        //manual    
        if(!strcmp(argv[0], "./prog") && !strcmp(argv[1],"-h")){
            print_usage();
            exit(1);
        }
        //program
        else if(!strcmp(argv[0], "./prog") && strlen(argv[2])>=7 && strlen(argv[2])<=15){
            //設定TTL
            max_hopping = atoi(argv[1]);

            //expanding ring search
            for(TTL=1; TTL<=max_hopping; TTL++){
                //初始化IP header
                memset(&IP_send_header, 0, sizeof(IP_send_header));
                IP_send_header.sin_family = AF_INET;
                IP_send_header.sin_addr.s_addr = inet_addr(argv[2]);

                //設定IP封包的TTL
                setsockopt(soc_send, IPPROTO_IP, IP_TTL, (char *)&TTL, sizeof(TTL));

                //初始化 ICMP Header
                memset(&ICMP_send_header, 0, sizeof(ICMP_send_header));
                ICMP_send_header.type = ICMP_ECHO;
                ICMP_send_header.code = 0;
                ICMP_send_header.checksum = 0;
                ICMP_send_header.un.echo.id = 0;
                ICMP_send_header.un.echo.sequence = 0;
                ICMP_send_header.checksum = checksum((unsigned short*)&ICMP_send_header, sizeof(ICMP_send_header)); //計算checksum

                // 將定義好的 ICMP Header 送到 destination
                network_number = sendto(soc_send, (char*)&ICMP_send_header, sizeof(ICMP_send_header), 0, (struct sockaddr*)&IP_send_header, sizeof(IP_send_header));
                if(network_number < 1){
                    perror("sendto");
                    exit(-1);
                }
                else{
                    printf("an ICMP packet has been sent to %s\n", argv[2]);
                }

                // 清空 buffer
                memset(buffer, 0, sizeof(buffer));

                printf("Waiting for ICMP echo reply...\n");

                // 接收來自目標主機的 Echo Reply
                int IP_size = sizeof(received_IP);
                network_number = recvfrom(soc_recv, buffer, sizeof(buffer), 0, (struct sockaddr *)&received_IP, &IP_size);
                if(network_number < 1){
                    perror("recv");
                    exit(1);
                }

                // 取出 IP Header
                IP_recv_header = (struct iphdr*)buffer;
                // 取出 ICMP Header
                ICMP_recv_header = (struct icmphdr*)(buffer+(IP_recv_header->ihl)*4);

                /*判斷ICMP type*/
                //ICMP echo reply
                if(ICMP_recv_header->type == 0 && ICMP_recv_header->code == 0){
                    printf("Now TTL = %d\n", TTL);
                    printf("The host %s is alive\n", argv[2]);
                    break;
                }
                //time exceeded
                else if(ICMP_recv_header->type == 11 && ICMP_recv_header->code == 0){
                    printf("Now TTL = %d\n", TTL);
                    printf("%s\n", "Time exceeded!");
                    printf("The router ip is %s\n", inet_ntoa(received_IP.sin_addr));
                }
                else{
                    printf("Have another situations!\n");
                    printf("The ICMP type is %d\n", ICMP_recv_header->type);
                    printf("The ICMP code is %d\n", ICMP_recv_header->code);
                }

                printf("\n");
                printf("--------------------------------------------");
                printf("\n\n");
            }
        }
        //exception
        else{
            printf("Please enter the correct command!");
        }
    }
    return 0;
}
