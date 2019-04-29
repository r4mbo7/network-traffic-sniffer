#include "tcp.h"

void affichage_tcp(User *user, TcpHdr *h){

	couleur("34");
	if(user->opt->v == 3){
		printf("TCP   ");
		printf("\t\t Sport : %d \t\t Dport : %d\n", h->th_sport, h->th_dport);
		printf("\t\t Seq : %u\n", h->th_seq);
		printf("\t\t Ack : %u\n", h->th_ack);
		printf("\t\t OffSet : %d\n", h->th_off);
		printf("\t\t");
		if(TH_FIN&((h->th_flags)&(1u<<0))){
			printf(" FIN");
		}
		if(TH_SYN&((h->th_flags)&(1u<<1))){
			printf(" SYN");
		}
		if(TH_RST&((h->th_flags)&(1u<<2))){
			printf(" RST");
		}
		if(TH_PUSH&((h->th_flags)&(1u<<3))){
			printf(" PUSH");
		}
		if(TH_ACK&((h->th_flags)&(1u<<4))){
			printf(" ACK");
		}
		if(TH_URG&((h->th_flags)&(1u<<5))){
			printf(" URG");
		}
		couleur("0");
		printf("\n");
	}
	else if(user->opt->v == 2){
		printf("TCP   ");
		printf("\t Port source: %d \t Port destination: %d", h->th_sport, h->th_dport);
		if(TH_FIN&((h->th_flags)&(1u<<0))){
			printf(" FIN");
		}
		if(TH_SYN&((h->th_flags)&(1u<<1))){
			printf(" SYN");
		}
		if(TH_RST&((h->th_flags)&(1u<<2))){
			printf(" RST");
		}
		if(TH_PUSH&((h->th_flags)&(1u<<3))){
			printf(" PUSH");
		}
		if(TH_ACK&((h->th_flags)&(1u<<4))){
			printf(" ACK");
		}
		if(TH_URG&((h->th_flags)&(1u<<5))){
			printf(" URG");
		}
		couleur("0");
		printf("\n");
	}
	else{
		printf("pS:%d pD:%d ", h->th_sport, h->th_dport);		
		couleur("0");
		printf(" ");
	}

}

void analyse_tcp(User *user, const u_char *bytes){

	TcpHdr *h = malloc(sizeof(struct tcphdr));

	h->th_sport = (u_int16_t)bytes[0];
	h->th_sport = ((h->th_sport)<<8)|(u_int16_t)bytes[1];

	h->th_dport = (u_int16_t)bytes[2];
	h->th_dport = ((h->th_dport)<<8)|(u_int16_t)bytes[3];

	h->th_seq = (u_int32_t)bytes[4];
	h->th_seq = ((h->th_seq)<<8)|(u_int32_t)bytes[5];
	h->th_seq = ((h->th_seq)<<8)|(u_int32_t)bytes[6];
	h->th_seq = ((h->th_seq)<<8)|(u_int32_t)bytes[7];

	h->th_ack = (u_int32_t)bytes[8];
	h->th_ack = ((h->th_ack)<<8)|(u_int32_t)bytes[9];
	h->th_ack = ((h->th_ack)<<8)|(u_int32_t)bytes[10];
	h->th_ack = ((h->th_ack)<<8)|(u_int32_t)bytes[11];

	h->th_off = bytes[12]>>4;

	h->th_x2 = bytes[12];

	h->th_flags = bytes[13];

	h->th_win = bytes[14];
	h->th_win = ((h->th_win)<<8)|(u_int16_t)bytes[15];

	h->th_sum = bytes[15];
	h->th_sum = ((h->th_sum)<<8)|(u_int16_t)bytes[16];

	h->th_urp = bytes[17];
	h->th_urp = ((h->th_urp)<<8)|(u_int16_t)bytes[18];

	if(user->opt->v >=1 ){
		affichage_tcp(user, h);
	}
	
	switch(h->th_dport){
		case 80:
			analyse_http(user, &bytes[4*h->th_off]);
			break;
		case 443:
			printf("HTTPS\n");
			break;
		case 53:
			analyse_dns(user, &bytes[4*h->th_off]);
			break;
		case 20:
			analyse_ftp(user, &bytes[4*h->th_off]);
			break;
		case 21:
			analyse_ftp(user, &bytes[4*h->th_off]);
			break;
		case 23:
			analyse_telnet(user, &bytes[4*h->th_off]);
			break;
		case 25:
			analyse_smtp(user, &bytes[4*h->th_off]);
			break;
		case 110:
			analyse_pop(user, &bytes[4*h->th_off]);
			break;
		case 143:
		case 993:
			analyse_imap(user, &bytes[4*h->th_off]);
			break;
		default:
			switch(h->th_sport){
				case 80:
					analyse_http(user, &bytes[4*h->th_off]);
					break;
				case 443:
					printf("HTTPS\n");
				case 53:
					analyse_dns(user, &bytes[4*h->th_off]);
					break;
				case 20:
					analyse_ftp(user, &bytes[4*h->th_off]);
					break;
				case 21:
					analyse_ftp(user, &bytes[4*h->th_off]);
					break;
				case 23:
					analyse_telnet(user, &bytes[4*h->th_off]);
					break;
				case 25:
					analyse_smtp(user, &bytes[4*h->th_off]);
					break;
				case 110:
					analyse_pop(user, &bytes[4*h->th_off]);
					break;
				case 143:
				case 993:
					analyse_imap(user, &bytes[4*h->th_off]);
					break;
				default:
					printf("Unknow (%d)\n", h->th_dport);
					break;
			}
			break;
	}


	/*
	if(h->th_dport == 80 || h->th_sport == 80){
		analyse_http(user, &bytes[4*h->th_off]);
	}
	*/
}