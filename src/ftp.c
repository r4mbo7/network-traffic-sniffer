#include "ftp.h"

void affichage_ftp(User *user, const u_char *bytes){
	switch(user->opt->v){
		case 3:
			print_hex_ascii_line(user, bytes);
			break;
		case 2:
			print_hex_ascii_line(user, bytes);
		default:
			break;
	}
}

void analyse_ftp(User *user, const u_char *bytes){
	affichage_ftp(user, bytes);
}