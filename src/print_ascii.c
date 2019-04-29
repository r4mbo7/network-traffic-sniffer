#include "print_ascii.h"
#include <ctype.h>

void print_ascii_line_len(User *user, const u_char *payload, int len){

	int i;
	const u_char *ch;
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
}

void print_hex_ascii_line(User *user, const u_char *payload){

	int i;
	int gap;
	int len = strlen((char *)payload);
	const u_char *ch;

	/* offset */
	//printf("%05d   ", offset);
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch)){
			printf("%c", *ch);
		}
		else if (*ch == '\n'){
			printf("\n");
		}
		else{
			printf(".");
		}
		ch++;
	}

	printf("\n");

	/*	--- hex --- */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	/*	--- hex ---	*/

	printf("\n");
}