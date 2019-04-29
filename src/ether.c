#include "ether.h"

#define	ETHERTYPE_PUP		0x0200          /* Xerox PUP */


void affichage_ethernet(User *user, EtherHdr *h){
	printf("\n-\t-\t-\t-\t-\t-\t-\n");
		couleur("33");
	if(user->opt->v == 3){
		printf("ethernet   ");
		printf("\n");
		printf("Adresse destination : %s\n", ether_ntoa((const struct ether_addr *)h->ether_dhost));
		printf("Adresse source : %s\n", ether_ntoa((const struct ether_addr *)h->ether_shost));
		printf("Type : %02X \t", h->ether_type);
		switch(h->ether_type){
			case ETHERTYPE_PUP:
				printf("Xerox PUP\n");
				break;
			case ETHERTYPE_SPRITE :
				printf("Sprite");
				break;
			case ETHERTYPE_IP:
				printf("IPv4");
				break;
			case ETHERTYPE_ARP:
				printf("Address resolution");
				break;
			case ETHERTYPE_REVARP:
				printf("Reverse ARP");
				break;
			case ETHERTYPE_AT:
				printf("AppleTalk protocol");
				break;
			case ETHERTYPE_AARP:
				printf("AppleTalk ARP");
				break;
			case ETHERTYPE_VLAN:
				printf("IEEE 802.1Q VLAN tagging");
				break;
			case ETHERTYPE_IPX:
				printf("IPX");
				break;
			case ETHERTYPE_IPV6:
				printf("IP protocol version 6");
				break;
			case ETHERTYPE_LOOPBACK:
				printf("used to test interfaces");
				break;
			default:
				printf("... %02X?", h->ether_type);
				break;
		}
		couleur("0");
		printf("\n");
	}
	else if(user->opt->v == 2){
		printf("ethernet   \t %s >>> %s \t", ether_ntoa((const struct ether_addr *)h->ether_dhost), ether_ntoa((const struct ether_addr *)h->ether_shost));
		couleur("0");
		printf("\n");
	}
	else{
		couleur("0");
		printf(" ");
	}
}

void analyse_ethernet(User *user, const u_char *bytes){

	EtherHdr *etherhdr = malloc(sizeof(struct ether_header));
	
	int i;
	for(i=0; i<6; i++){
		etherhdr->ether_dhost[i] = bytes[i];
	}

	for(i=6; i<12; i++){
		etherhdr->ether_shost[i-6] = bytes[i];
	}

	etherhdr->ether_type = (u_int16_t)bytes[12];
	etherhdr->ether_type = ((etherhdr->ether_type)<<8)|(u_int16_t)bytes[13];

	if(user->opt->v >= 1){
		affichage_ethernet(user, etherhdr);
	}

	switch(etherhdr->ether_type){
		case ETHERTYPE_PUP:
			break;
		case ETHERTYPE_SPRITE :
			break;
		case ETHERTYPE_IP:
			analyse_ipv4(user, &bytes[14]);
			break;
		case ETHERTYPE_ARP:
			analyse_arp(user, &bytes[14]);
			break;
		case ETHERTYPE_REVARP:
			break;
		case ETHERTYPE_AT:
			break;
		case ETHERTYPE_AARP:
			break;
		case ETHERTYPE_VLAN:
			break;
		case ETHERTYPE_IPX:
			break;
		case ETHERTYPE_IPV6:
			break;
		case ETHERTYPE_LOOPBACK:
			break;
		default:
			break;
	}
}