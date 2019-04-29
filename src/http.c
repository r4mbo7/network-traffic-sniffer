#include "http.h"
#include "print_ascii.h"
#include <ctype.h>

void affichage_http(User *user, const u_char *bytes){

	
	printf("HTTP ");
	switch(user->opt->v){
		case 3:
			print_hex_ascii_line(user, bytes);
			break;
		case 2:
			if(isprint(*bytes)){
				print_ascii_line_len(user, bytes, 100);
			}
			break;
		default:
			if(isprint(*bytes)){
				print_ascii_line_len(user, bytes, 80);
			}
			break;
	}

}

void analyse_http(User *user, const u_char *bytes){
	affichage_http(user, bytes);
}