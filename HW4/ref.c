#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <unistd.h>

// print function command
void print_function(){
    printf("[Prog Command]\n");
    printf("Format :\n");
    printf("1) ./prog <hop-distance> <destination>\n");
}

// calculate checksum
unsigned short checksum(unsigned short *buf, int bufsz){
    unsigned long sum = 0xffff;

    while(bufsz > 1){
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if(bufsz == 1)
        sum += *(unsigned char*)buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int main(int argc, char *argv[]){ 
    struct sockaddr_in IP_recv; // declare recive IP
    struct sockaddr_in IPheader_send; // declare send IP header
    struct iphdr *IPheader_recv; // declare recive IP header
    struct icmphdr ICMPheader_send; // declare ICMP header
    struct icmphdr *ICMPheader_recv; // declare recive ICMP header

    int sockfd_recv, sockfd_send;
    int time=1;
    int time_limit;
    int IP_recv_size=sizeof(IP_recv);

    char buffer[1024];

    if(geteuid() != 0){
        printf("ERROR: You must be root to use this tool!\n");
        exit(1);
    }

    // open one recceived socket in ip layer
    if((sockfd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        perror("open recv socket error");
        exit(1);
    }
    
    // open one send socket in ip layer
    if((sockfd_send = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        perror("open send socket error");
        exit(1);
    }

    if(argc==2 && !strcmp(argv[0],"./prog") && !strcmp(argv[1],"-h")){
        print_function();
        exit(1);
    }
    else if(argc==3 && strlen(argv[2])>=7 && strlen(argv[2])<=15){
        // set TTL
        time_limit = atoi(argv[1]);

        // set IP header
        // initialization IP header
        memset(&IPheader_send, 0, sizeof(IPheader_send));  
        IPheader_send.sin_family = AF_INET;
        IPheader_send.sin_addr.s_addr = inet_addr(argv[2]);
        // set TTL in IP header
        setsockopt(sockfd_send, IPPROTO_IP, IP_TTL, (char *)&time, sizeof(IP_TTL));

        // set ICMP header
        // initialization ICMP header
        memset(&ICMPheader_send, 0, sizeof(ICMPheader_send));
        ICMPheader_send.type = 8;
        ICMPheader_send.code = 0;
        ICMPheader_send.un.echo.id = 0;
        ICMPheader_send.un.echo.sequence = 0;
        // calculate ICMP checksum
        ICMPheader_send.checksum = checksum((unsigned short*)&ICMPheader_send, sizeof(ICMPheader_send));
        
        // send ICMP echo request to destination
        if(sendto(sockfd_send, (char*)&ICMPheader_send, sizeof(ICMPheader_send), 0, (struct sockaddr*)&IPheader_send, sizeof(IPheader_send))<0){
            perror("sendto");
            exit(1);
        }
        else{
            printf("%d) Send an ICMP echo request packet to %s\n", time, argv[2]);
        }

        while(1){
            // initialization
            memset(buffer, 0, sizeof(buffer));

            // recive ICMP message
            if(recvfrom(sockfd_recv,buffer,sizeof(buffer),0,(struct sockaddr *)&IP_recv,&IP_recv_size)<0){
                perror("recv");
                exit(1);
            }

            // get IP header form recive ICMP message
            IPheader_recv = (struct iphdr*)buffer;
            // get ICMP header form recive ICMP message
            ICMPheader_recv = (struct icmphdr*)(buffer+(IPheader_recv->ihl)*4);

            if(ICMPheader_recv->type == 0 && ICMPheader_recv->code == 0){
                printf("TTL = %d\n",time);
                printf("The host %s is alive!\n",argv[2]);
                break;
            }
            else if(ICMPheader_recv->type == 11 && ICMPheader_recv->code == 0){
                printf("TTL = %d\n",time);
                printf("The packet send to %s is Time Exceeded!\n",argv[2]);
                printf("The router ip is %s\n", inet_ntoa(IP_recv.sin_addr));
            }
            //else if()
            //{
            // printf("The recive socket find this ICMP is time out\n");
            // printf("It will plus one to TTL send next ICMP\n");
            // printf("\n");
            //}
            else{
                printf("Have another situations!\n");
                printf("The ICMP type is %d\n", ICMPheader_recv->type);
                printf("The ICMP code is %d\n", ICMPheader_recv->code);
            }

            // time out
            if(time>time_limit){
                break;
            }
            else{
                // update TTL
                time = time + 1;

                // set IP header
                // initialization IP header
                memset(&IPheader_send, 0, sizeof(IPheader_send));  
                IPheader_send.sin_family = AF_INET;
                IPheader_send.sin_addr.s_addr = inet_addr(argv[2]);
                // set TTL in IP header
                setsockopt(sockfd_send, IPPROTO_IP, IP_TTL, (char *)&time, sizeof(IP_TTL));

                // set ICMP header
                // initialization ICMP header
                memset(&ICMPheader_send, 0, sizeof(ICMPheader_send));
                ICMPheader_send.type = 8;
                ICMPheader_send.code = 0;
                ICMPheader_send.un.echo.id = 0;
                ICMPheader_send.un.echo.sequence = 0;
                // calculate ICMP checksum
                ICMPheader_send.checksum = checksum((unsigned short*)&ICMPheader_send, sizeof(ICMPheader_send));
            
                // send ICMP echo request to destination
                if(sendto(sockfd_send, (char*)&ICMPheader_send, sizeof(ICMPheader_send), 0, (struct sockaddr*)&IPheader_send, sizeof(IPheader_send))<0){
                perror("sendto");
                exit(1);
                }
                else{
                printf("\n");
                printf("%d) Send an ICMP echo request packet to %s\n", time, argv[2]);
                }
            } 
        }
    }

    else{
        printf("Command Error!!\n");
        printf("Use -h to check function\n");
    }
}
