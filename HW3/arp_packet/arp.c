#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type){
	packet -> ea_hdr.ar_hrd = type;
}

void set_prot_type(struct ether_arp *packet, unsigned short int type){
	packet -> ea_hdr.ar_pro = type;
}

void set_hard_size(struct ether_arp *packet, unsigned char size){
	packet ->ea_hdr.ar_hln = size;
}

void set_prot_size(struct ether_arp *packet, unsigned char size){
	packet -> ea_hdr.ar_pln = size;
}

void set_op_code(struct ether_arp *packet, short int code){
	packet -> ea_hdr.ar_op = code;
}


void set_sender_hardware_addr(struct ether_arp *packet, unsigned char *address){

}

void set_sender_protocol_addr(struct ether_arp *packet, char *address){

}

void set_target_hardware_addr(struct ether_arp *packet, char *address){

}

void set_target_protocol_addr(struct ether_arp *packet, char *address){

}


char* get_sender_protocol_addr(struct ether_arp *packet){
	struct in_addr send_address;
	memcpy(&send_address, packet->arp_tpa,4);
	return inet_ntoa(send_address);
}

char* get_target_protocol_addr(struct ether_arp *packet){
	struct in_addr target_address;
	memcpy(&target_address, packet->arp_spa,4);
	return inet_ntoa(target_address);
}

char* get_sender_hardware_addr(struct ether_arp *packet){
	struct ether_addr send_mac;
	char Sendmac[32];
	memcpy(&send_mac,packet->arp_sha,6);
	return ether_ntoa_r(&send_mac,Sendmac);
}

char* get_target_hardware_addr(struct ether_arp *packet){
	//unknown
}
