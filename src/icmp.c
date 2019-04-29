#include "icmp.h"

void affichage_icmp(User *user, IcmpHdr *icmphdr){
	couleur("31");
	if(user->opt->v == 3){
		printf("\t\t ICMP\n");
		printf("\t\t (Type, Code) = (%d, %d)", icmphdr->type, icmphdr->code);
		couleur("0");
		printf("\n");
	}	
	else if(user->opt->v == 2){
		printf("ICMP   ");	
		printf("\t (Type, Code) = (%d, %d)", icmphdr->type, icmphdr->code);
		couleur("0");
		printf("\n");
	}
	else{
		printf(" ICMP ");
		couleur("0");
		printf(" ");
	}
	/*
	printf("\t\t id : %d\n", icmphdr->echo->id);
	printf("\t\t sequence : %d\n", icmphdr->echo->sequence);
	*/
}

void analyse_icmp(User *user, const u_char *bytes){

	IcmpHdr *icmphdr = malloc(sizeof(IcmpHdr));

	icmphdr = (IcmpHdr *)bytes;

	/*icmphdr->type = bytes[0];
	icmphdr->code = bytes[1];

	icmphdr->checksum = (u_int16_t)bytes[2];
	icmphdr->checksum = ((icmphdr->checksum)<<8)|(u_int16_t)bytes[3];
	icmphdr->echo->id = (u_int16_t)bytes[3];
	icmphdr->echo->id = ((icmphdr->echo->id)<<8)|(u_int16_t)bytes[4];

	icmphdr->echo->sequence = (u_int16_t)bytes[5];
	icmphdr->echo->sequence = ((icmphdr->echo->sequence)<<8)|(u_int16_t)bytes[6];
	*/

	if(user->opt->v >= 1){
		affichage_icmp(user, icmphdr);
	}
}