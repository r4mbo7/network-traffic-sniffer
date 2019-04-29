#ifndef _DNS_
#define _DNS_ value

#include "analyseur.h"

/*
 * DNS query / reply header
 */
typedef struct {
	u_int16_t xid;
	u_int16_t flags;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
} DnsHdr;

void analyse_dns(User *user, const u_char *bytes);

#endif