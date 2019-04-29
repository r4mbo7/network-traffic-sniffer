#include "udp.h"

void affichage_udp(User *user, UdpHdr *udp){

	couleur("32");
	if(user->opt->v == 3){
		printf("UDP   ");
		printf("\t\t Sport : %d \t\t Dport : %d\n", udp->source, udp->dest);
		printf("\t\t len : %d \t\t Check : %d", udp->len, udp->check);
	}
	else if(user->opt->v == 2){
		printf("UDP   ");
		printf("\t Port source : %d \t Port destination : %d", udp->source, udp->dest);		
		
	}
	else{
		printf("ps:%d pd:%d ", udp->source, udp->dest);
	}
	couleur("0");
	if(user->opt->v > 1){
		printf("\n");
	}
	else{
		printf("\t");
	}
}

void analyse_udp(User *user, const u_char *bytes){

	UdpHdr *udp = malloc(sizeof(UdpHdr));

	udp->source = (u_int16_t)bytes[0];
	udp->source = ((udp->source)<<8)|(u_int16_t)bytes[1];

	udp->dest = (u_int16_t)bytes[2];
	udp->dest = ((udp->dest)<<8)|(u_int16_t)bytes[3];

	udp->len = (u_int16_t)bytes[4];
	udp->len = ((udp->len)<<8)|(u_int16_t)bytes[5];

	udp->check = (u_int16_t)bytes[6];
	udp->check = ((udp->check)<<8)|(u_int16_t)bytes[7];
		
	if(user->opt->v >= 1){
		affichage_udp(user, udp);
	}

	switch(udp->dest){
		case 53:
			analyse_dns(user, &bytes[8]);
			break;
		case 67:
			analyse_bootp(user, &bytes[8]);
			break;
		case 1900:
			printf("SSDP\n");
			break;
		default:
			switch(udp->source){
				case 53:
					analyse_dns(user, &bytes[8]);
					break;
				case 67:
					analyse_bootp(user, &bytes[8]);
					break;
				case 1900:
					printf("SSDP\n");
					break;
				default:
					printf("Unknow\n");
			}
	}

}