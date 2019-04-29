#include "dns.h"
#include <math.h>

/* Unused function to show bytes of a u_int16_t var
unsigned int dtobin(u_int16_t h)
{
	double n;
	unsigned int b=0;
 
	for(n=0;n<=15;n++)
	{
		b+=(pow(10,n)*(h%2));
		h/=2;
	}
 	return b;
}
*/

void affichage_dns(User *user, DnsHdr *hdr, const u_char *bytes){

	couleur("34");
	printf("DNS\t");
	couleur("0");
	
	if(user->opt->v == 3){
		printf("\n");

		printf("id : %u\n", hdr->xid);

		//printf("%d\n", dtobin(hdr->flags));
		
		if(hdr->flags & 1u){
			printf("Reponse\n");
		}
		else{
			printf("Requete\n");
		}

		int qr = 0;
		qr |= ( hdr->flags & (1u << 1)) << 0;
		qr |= ( hdr->flags & (1u << 2)) << 1;
		switch(qr){
			case 0:
				printf("Query\n");
				break;
			case 1:
				printf("Iquery\n");
				break;
			case 2:
				printf("Status\n");
				break;
			default:
				printf("Qr unknow (%d)\n", qr);
		}

		if(hdr->flags & (1u << 5)){
			printf("Authoritative Answer\n");
		}

		if(hdr->flags & (1u << 6)){
			printf("Message tronqué\n");
		}

		if(hdr->flags & (1u << 7)){
			printf("Demande la récursivité\n");
		}

		if(hdr->flags & (1u << 8)){
			printf("Récursivité autorisée\n");
		}

		int rc = 0;
		rc |= ( hdr->flags & ( 1u << 1) ) << 12;
		rc |= ( hdr->flags & ( 1u << 2) ) << 13;
		switch(rc){
			case 0:
				printf("Pas d'erreur\n");
				break;
			case 1:
				printf("Erreur de format dans la requête\n");
				break;
			case 2:
				printf("Problème sur serveur\n");
				break;
			case 3:
				printf("Le nom n'existe pas\n");
				break;
			case 4:
				printf("Non implémenté\n");
				break;
			case 5:
				printf("Refus\n");
				break;
			default:
				printf("Rcode unknow (%d)\n", rc);
			break;
		}

		printf("Qdcount %u\t", hdr->qdcount);
		printf("Ancount %u\n", hdr->ancount);
		printf("Nscount %u\t", hdr->nscount);
		printf("Arcount %u\n", hdr->arcount);

		print_hex_ascii_line(user, bytes);
	}
	if(user->opt->v == 2){
		printf("\n");
	}
}

void analyse_dns(User *user, const u_char *bytes){
	DnsHdr *hdr = malloc(sizeof(DnsHdr));
	hdr = (DnsHdr *)bytes;
	affichage_dns(user, hdr, bytes);
}