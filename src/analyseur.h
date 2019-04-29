/*
gcc -o analyseur analyseur.c ether.c arp.c ipv4.c icmp.c tcp.c udp.c dns.c http.c bootp.c telnet.c print_ascii.c smtp.c pop.c imap.c ftp.c -lpcap -pthread
*/
#ifndef _ANALYSEUR_
#define _ANALYSEUR_

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/if_ppp.h>
#include <net/if_shaper.h>
#include <net/if_slip.h>
#include <net/ppp-comp.h>
#include <net/ppp_defs.h>
#include <net/route.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/if_fddi.h>
#include <netinet/if_tr.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
//#include <netinet/sctp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#define couleur(param) printf("\033[%sm",param)

typedef struct tm Date;

//Strucutre des options passer à l'éxécution de programme
typedef struct Option Option;
struct Option
{
	char *i;
	char *o;
	char *f;
	int v;
};

//Structure contenant les informations d'un paquet
typedef struct paquet Paquet;
struct paquet
{
	int num;
	bpf_u_int32 len;
	Date *date;
};

//List des paquets lus
typedef struct maillon *Liste;
struct maillon{
	Paquet *donnee;
	Liste suivant;
};

//Structure qui sert à véhiculer les informations concerant les options et les paquets
typedef struct User User;
struct User
{
	Option *opt;
	//Pour l'affichage avec clutter
	//ClutterActor *stage;
	Liste l_paquet;
	int nb_paquet;
};


typedef struct ether_header EtherHdr;

/* Header ARP */
typedef struct _arphdr ArpHdr;
struct _arphdr
  {
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
    /* Ethernet looks like this : This bit is variable sized
       however...  */
    unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */
  };

typedef struct iphdr IpHdr;

typedef struct tcphdr TcpHdr;
typedef struct udphdr UdpHdr;
typedef struct icmphdr IcmpHdr;

typedef struct bootp Bootp;


Liste cons(Liste l, Paquet *nvelt);
void start_analyse(User *user);

#include "print_ascii.h"

#include "ftp.h"
#include "smtp.h"
#include "pop.h"
#include "imap.h"
#include "telnet.h"
#include "http.h"
#include "dns.h"

#include "bootp.h"

#include "tcp.h"
#include "udp.h"
#include "icmp.h"

#include "ipv4.h"
#include "arp.h"

#include "ether.h"

#endif