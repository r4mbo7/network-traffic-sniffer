#include "telnet.h"
#include "print_ascii.h"

void affichage_telnet(User *user, const u_char *bytes){

	int n = 0, nego = 0, len = 0;

	if(bytes[0] == 255){
		
		nego = 1;
		len = strlen((char *)bytes);
		
		while (n < len && nego == 1){
			if(bytes[n]==255){
				switch(bytes[n+1]){
					case 241 :
						printf("NOP ");
						break;
					case 242 :
						printf("DM ");
						break;
					case 244 :
						printf("IP ");
						break;
					case 245 :
						printf("AO ");
						break;
					case 246 :
						printf("AYT ");
						break;
					case 247 :
						printf("EC ");
						break;
					case 248 :
						printf("EL ");
						break;
					case 249 :
						printf("GA ");
						break;
					case 250 :
						printf("SB ");
						break;
					case 240 :
						printf("SE ");
						nego = 0;
						break;
					case 251 :
						printf("WILL ");
						break;
					case 252 :
						printf("WON’T ");
						break; 
					case 253 :
						printf("DO ");
						break; 
					case 254 :
						printf("DON’T ");
						break; 
					case 255 :
						printf("IAC ");
						break;
					default:
						printf("Unknows %d\n", bytes[n+1]);
				}
				switch(bytes[n+2]){
					case 0:
						printf("TELNET_TELOPT_BINARY");
						break;
					case 1:
						printf("TELNET_TELOPT_ECHO");
						break;
					case 2:
						printf("TELNET_TELOPT_RCP");
						break;
					case 3:
						printf("TELNET_TELOPT_SGA");
						break;
					case 4:
						printf("TELNET_TELOPT_NAMS");
						break;
					case 5:
						printf("TELNET_TELOPT_STATUS");
						break;
					case 6:
						printf("TELNET_TELOPT_TM");
						break;
					case 7:
						printf("TELNET_TELOPT_RCTE");
						break;
					case 8:
						printf("TELNET_TELOPT_NAOL");
						break;
					case 9:
						printf("TELNET_TELOPT_NAOP");
						break;
					case 10:
						printf("TELNET_TELOPT_NAOCRD");
						break;
					case 11:
						printf("TELNET_TELOPT_NAOHTS");
						break;
					case 12:
						printf("TELNET_TELOPT_NAOHTD");
						break;
					case 13:
						printf("TELNET_TELOPT_NAOFFD");
						break;
					case 14:
						printf("TELNET_TELOPT_NAOVTS");
						break;
					case 15:
						printf("TELNET_TELOPT_NAOVTD");
						break;
					case 16:
						printf("TELNET_TELOPT_NAOLFD");
						break;
					case 17:
						printf("TELNET_TELOPT_XASCII");
						break;
					case 18:
						printf("TELNET_TELOPT_LOGOUT");
						break;
					case 19:
						printf("TELNET_TELOPT_BM");
						break;
					case 20:
						printf("TELNET_TELOPT_DET");
						break;
					case 21:
						printf("TELNET_TELOPT_SUPDUP");
						break;
					case 22:
						printf("TELNET_TELOPT_SUPDUPOUTPUT");
						break;
					case 23:
						printf("TELNET_TELOPT_SNDLOC");
						break;
					case 24:
						printf("TELNET_TELOPT_TTYPE");
						break;
					case 25:
						printf("TELNET_TELOPT_EOR");
						break;
					case 26:
						printf("TELNET_TELOPT_TUID");
						break;
					case 27:
						printf("TELNET_TELOPT_OUTMRK");
						break;
					case 28:
						printf("TELNET_TELOPT_TTYLOC");
						break;
					case 29:
						printf("TELNET_TELOPT_3270REGIME");
						break;
					case 30:
						printf("TELNET_TELOPT_X3PAD");
						break;
					case 31:
						printf("TELNET_TELOPT_NAWS");
						break;
					case 32:
						printf("TELNET_TELOPT_TSPEED");
						break;
					case 33:
						printf("TELNET_TELOPT_LFLOW");
						break;
					case 34:
						printf("TELNET_TELOPT_LINEMODE");
						break;
					case 35:
						printf("TELNET_TELOPT_XDISPLOC");
						break;
					case 36:
						printf("TELNET_TELOPT_ENVIRON");
						break;
					case 37:
						printf("TELNET_TELOPT_AUTHENTICATION");
						break;
					case 38:
						printf("TELNET_TELOPT_ENCRYPT");
						break;
					case 39:
						printf("TELNET_TELOPT_NEW_ENVIRON");
						break;
					case 70:
						printf("TELNET_TELOPT_MSSP");
						break;
					case 85:
						printf("TELNET_TELOPT_COMPRESS");
						break;
					case 86:
						printf("TELNET_TELOPT_COMPRESS2");
						break;
					case 93:
						printf("TELNET_TELOPT_ZMP");
						break;
					case 255:
						printf("TELNET_TELOPT_EXOPL");
						break;
					default:
						printf("Unknows (%d)", bytes[n+2]);
						break;
				}
				switch(user->opt->v){
					case 3:
					case 2:
						printf("\n");
						break;
					default:
						printf("\t");
						break;
				}
			}
			n += 1;
		}
	}

	switch(user->opt->v){
		case 3:
			print_hex_ascii_line(user, bytes);
			break;
		case 2:
			print_ascii_line_len(user, &(bytes[len-n]), 30);
		default:
			break;
	}
}

void analyse_telnet(User *user, const u_char *bytes){
	affichage_telnet(user, bytes);
}