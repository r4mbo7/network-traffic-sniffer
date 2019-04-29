#include "ipv4.h"

void affichage_ipv4(User *user, IpHdr *iphdr){
	if(user->opt->v == 3){
		printf("IPv4   ");
		printf("\tV:%d\t", iphdr->version);
		printf("\tihl:%d\n", iphdr->ihl);
		printf("\ttos:%d\n", iphdr->tos);
		printf("\ttot_len:%d\n", iphdr->tot_len);
		printf("\tid:%d\n", iphdr->id);
		printf("\tfrag_off:%d\n", iphdr->frag_off);
		printf("\tttl:%d\n", iphdr->ttl);

		printf("\tsaddr:%u.%u.%u.%u \t>\t ", (u_int8_t)(iphdr->saddr>>24), (u_int8_t)(iphdr->saddr>>16), (u_int8_t)(iphdr->saddr>>8), (u_int8_t)(iphdr->saddr));
		printf("\tdaddr:%u.%u.%u.%u\t", (u_int8_t)(iphdr->daddr>>24), (u_int8_t)(iphdr->daddr>>16), (u_int8_t)(iphdr->daddr>>8), (u_int8_t)iphdr->daddr);
		printf("\tprotocol:%d\t", iphdr->protocol);

		switch(iphdr->protocol){
			case 0x01:
				printf("ICMP\n");
				break;
			case 0x06:
				printf("TCP\n");
				break;
			case 0x11:
				printf("UDP\n");
				break;
			default:
				printf("IPv4 protocol ...%02X?\n", iphdr->protocol);
				break;
		}
	}
	else if(user->opt->v == 2){
		printf("IPv4   ");
		printf("\t %u.%u.%u.%u >>> ", (u_int8_t)(iphdr->saddr>>24), (u_int8_t)(iphdr->saddr>>16), (u_int8_t)(iphdr->saddr>>8), (u_int8_t)(iphdr->saddr));
		printf("%u.%u.%u.%u\n", (u_int8_t)(iphdr->daddr>>24), (u_int8_t)(iphdr->daddr>>16), (u_int8_t)(iphdr->daddr>>8), (u_int8_t)iphdr->daddr);
	}
	else{
		printf("%u.%u.%u.%u >>> ", (u_int8_t)(iphdr->saddr>>24), (u_int8_t)(iphdr->saddr>>16), (u_int8_t)(iphdr->saddr>>8), (u_int8_t)(iphdr->saddr));
		printf("%u.%u.%u.%u ", (u_int8_t)(iphdr->daddr>>24), (u_int8_t)(iphdr->daddr>>16), (u_int8_t)(iphdr->daddr>>8), (u_int8_t)iphdr->daddr);		
	}
}

void analyse_ipv4(User *user, const u_char *bytes){

	IpHdr *iphdr = malloc(sizeof(struct iphdr));

	iphdr->version = bytes[0]>>4;

	iphdr->ihl = bytes[0];

	iphdr->tos = bytes[1];

	iphdr->tot_len = bytes[2];
	iphdr->tot_len = ((iphdr->tot_len)<<8)|bytes[3];

	iphdr->id = bytes[4];
	iphdr->id = ((iphdr->id)<<8)|bytes[5];

	iphdr->frag_off = bytes[6];
	iphdr->frag_off = ((iphdr->frag_off)<<8)|bytes[7];

	iphdr->ttl = bytes[8];

	iphdr->protocol = bytes[9];

	iphdr->check = (u_int16_t)bytes[10];
	iphdr->check = ((iphdr->check)<<8)|(u_int16_t)bytes[11];

	iphdr->saddr = (u_int32_t)bytes[12];
	iphdr->saddr = ((iphdr->saddr)<<8)|(u_int32_t)bytes[13];
	iphdr->saddr = ((iphdr->saddr)<<8)|(u_int32_t)bytes[14];
	iphdr->saddr = ((iphdr->saddr)<<8)|(u_int32_t)bytes[15];


	iphdr->daddr = (u_int32_t)bytes[16];
	iphdr->daddr = ((iphdr->daddr)<<8)|(u_int32_t)bytes[17];
	iphdr->daddr = ((iphdr->daddr)<<8)|(u_int32_t)bytes[18];
	iphdr->daddr = ((iphdr->daddr)<<8)|(u_int32_t)bytes[19];

	if(user->opt->v >=1 ){
		affichage_ipv4(user, iphdr);
	}
	
	switch(iphdr->protocol){
		case 0x01:
			analyse_icmp(user, &bytes[4*iphdr->ihl]);
			break;
		case 0x06:
			analyse_tcp(user, &bytes[4*iphdr->ihl]);
			break;
		case 0x11:
			analyse_udp(user, &bytes[4*iphdr->ihl]);
			break;
		default:
			printf("...%02X?\n", iphdr->protocol);
			break;
	}

	free(iphdr);
}