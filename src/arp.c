#include "arp.h"

/**
 * @brief Affiche les information sur le header
 * @details Affichage en fonction de la verbosité
 * 
 * @param user
 * @param arphdr
 */
void affichage_arp(User *user, ArpHdr *arphdr){
	if(user->opt->v == 3){
		printf("ARP   ");
		printf("\n");
		printf("Format of hardware address : %d\n", arphdr->ar_hrd);
		printf("Format of protocol address : %d\n", arphdr->ar_pro);
		printf("Length oh hardware address : %d\n", arphdr->ar_hln);
		printf("Length oh protocol address : %d\n", arphdr->ar_pln);
		printf("ARP opcode (command) : %d\n", arphdr->ar_op);
		printf("Sender hardware address : %s\n", ether_ntoa((const struct ether_addr *)arphdr->__ar_sha));
		printf("Send IP address : %d.%d.%d.%d\n",  arphdr->__ar_sip[0], arphdr->__ar_sip[1], arphdr->__ar_sip[2], arphdr->__ar_sip[3]);
		printf("Target hardware address : %s\n", ether_ntoa((const struct ether_addr *)arphdr->__ar_tha));
		printf("Target IP address : %d.%d.%d.%d\n",  arphdr->__ar_tip[0], arphdr->__ar_tip[1], arphdr->__ar_tip[2], arphdr->__ar_tip[3]);
	}
	else if(user->opt->v == 2){	
		printf("ARP   ");
		printf("\t %d.%d.%d.%d >>>",  arphdr->__ar_sip[0], arphdr->__ar_sip[1], arphdr->__ar_sip[2], arphdr->__ar_sip[3]);
		printf("%d.%d.%d.%d \n",  arphdr->__ar_tip[0], arphdr->__ar_tip[1], arphdr->__ar_tip[2], arphdr->__ar_tip[3]);
	}
	else{
		printf("ARP ");
		printf("\t %d.%d.%d.%d >>>",  arphdr->__ar_sip[0], arphdr->__ar_sip[1], arphdr->__ar_sip[2], arphdr->__ar_sip[3]);
		printf("%d.%d.%d.%d ",  arphdr->__ar_tip[0], arphdr->__ar_tip[1], arphdr->__ar_tip[2], arphdr->__ar_tip[3]);
	}
}

void analyse_arp(User *user, const u_char *bytes){

	ArpHdr *arphdr = malloc(sizeof(ArpHdr));

	arphdr->ar_hrd = (u_short)bytes[0];
	arphdr->ar_hrd = ((arphdr->ar_hrd)<<8)|(u_short)bytes[1];

	arphdr->ar_pro = (u_short)bytes[2];
	arphdr->ar_pro = ((arphdr->ar_pro)<<8)|(u_short)bytes[3];

	arphdr->ar_hln = bytes[4];
	arphdr->ar_pln = bytes[5];

	arphdr->ar_op = (u_short)bytes[6];
	arphdr->ar_op = ((arphdr->ar_op)<<8)|(u_short)bytes[7];

	int i;
	for(i=0; i < arphdr->ar_hln; i++){
		arphdr->__ar_sha[i] = bytes[8+i];
		arphdr->__ar_tha[i] = bytes[8+arphdr->ar_pln+i];
	}

	for(i=0; i < arphdr->ar_pln; i++){
		arphdr->__ar_sip[i] = bytes[8+arphdr->ar_hln+i];
		arphdr->__ar_tip[i] = bytes[8+2*arphdr->ar_hln+arphdr->ar_pln+i];
	}

	if(user->opt->v >= 1){
		affichage_arp(user, arphdr);
	}
}