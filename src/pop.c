#include "pop.h"

void affichage_pop(User *user, const u_char *bytes){

	printf("POP : ");
	switch(user->opt->v){
		case 3:
			print_hex_ascii_line(user, bytes);
			break;
		case 2:
			print_ascii_line_len(user, bytes, 30);
			break;
		default:
			print_ascii_line_len(user, bytes, 20);
			break;
	}
	printf("\n");

}

void analyse_pop(User *user, const u_char *bytes){
	affichage_pop(user, bytes);
}