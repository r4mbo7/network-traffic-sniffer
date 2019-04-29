#include "bootp.h"
/**
 * @brief Affiche les information sur le header
 * @details Affichage en fonction de la verbosité
 * 
 * @param user 
 * @param bootp 
 * @param bytes 
 */
void affichage_bootp(User *user, Bootp *bootp, const u_char *bytes){

	printf("Bootp   ");

	if(user->opt->v == 3){
	printf("op:%u \t htype:%u \n", bootp->bp_op, bootp->bp_htype);
	printf("\t hlen:%u \t hops:%u \n", bootp->bp_hlen, bootp->bp_hops);
	printf("\t xid:%u \t secs:%u \t flags:%02X\n", bootp->bp_xid, bootp->bp_secs, bootp->bp_flags);

	printf("\t Client IP addr :\t%s\n", inet_ntoa(bootp->bp_ciaddr));
	printf("\t Your IP addr :\t%s\n", inet_ntoa(bootp->bp_yiaddr));
	printf("\t Server IP addr :\t%s\n", inet_ntoa(bootp->bp_siaddr));
	printf("\t Gateway IP addr :\t%s\n", inet_ntoa(bootp->bp_giaddr));

	printf("\t Client hardware address :\t%s\n", ether_ntoa((const struct ether_addr *)bootp->bp_chaddr));
	printf("\t Server host name : \t%s\n", bootp->bp_sname);
	printf("\t Boot file name : \t%s\n", bootp->bp_file);
	}

	u_int8_t magic_cookie[4] = VM_RFC1048;
	if(memcmp(bootp->bp_vend, magic_cookie, 4) == 0){
		//printf("\t Magic cookie ! %d\n", user->l_paquet->donnee->len);
		int n = 240, i;
		int type = bytes[n], longueur;
		while(type){

			printf("T:%d ", type);

			switch(type){
				case TAG_PAD		:
					printf("TAG_PAD\t");
					break;				
				case TAG_SUBNET_MASK	:
					printf("TAG_SUBNET_MASK\t");
					break;				
				case TAG_TIME_OFFSET	:
					printf("TAG_TIME_OFFSET\t");
					break;				
				case TAG_GATEWAY	:
					printf("TAG_GATEWAY\t");
					break;				
				case TAG_TIME_SERVER	:
					printf("TAG_TIME_SERVER\t");
					break;				
				case TAG_NAME_SERVER	:
					printf("TAG_NAME_SERVER\t");
					break;				
				case TAG_DOMAIN_SERVER:
					printf("TAG_DOMAIN_SERVER\t");
					break;				
				case TAG_LOG_SERVER	:
					printf("TAG_LOG_SERVER\t");
					break;				
				case TAG_COOKIE_SERVER:
					printf("TAG_COOKIE_SERVER\t");
					break;				
				case TAG_LPR_SERVER	:
					printf("TAG_LPR_SERVER\t");
					break;				
				case TAG_IMPRESS_SERVER:
					printf("TAG_IMPRESS_SERVER\t");
					break;				
				case TAG_RLP_SERVER	:
					printf("TAG_RLP_SERVER\t");
					break;				
				case TAG_HOSTNAME	:
					printf("TAG_HOSTNAME\t");
					break;				
				case TAG_BOOTSIZE	:
					printf("TAG_BOOTSIZE\t");
					break;				
				case TAG_END		:
					printf("TAG_END\t");
					break;/* RFC1497 tags */
				
				case TAG_DUMPPATH	:
					printf("TAG_DUMPPATH\t");
					break;				
				case TAG_DOMAINNAME	:
					printf("TAG_DOMAINNAME\t");
					break;				
				case TAG_SWAP_SERVER	:
					printf("TAG_SWAP_SERVER\t");
					break;				
				case TAG_ROOTPATH:
					printf("TAG_ROOTPATH\t");
					break;				
				case TAG_EXTPATH	:
					printf("TAG_EXTPATH\t");
					break;/* RFC2132 */
				
				case TAG_IP_FORWARD	:
					printf("TAG_IP_FORWARD\t");
					break;				
				case TAG_NL_SRCRT	:
					printf("TAG_NL_SRCRT\t");
					break;				
				case TAG_PFILTERS	:
					printf("TAG_PFILTERS\t");
					break;				
				case TAG_REASS_SIZE	:
					printf("TAG_REASS_SIZE\t");
					break;				
				case TAG_DEF_TTL	:
					printf("TAG_DEF_TTL\t");
					break;				
				case TAG_MTU_TIMEOUT	:
					printf("TAG_MTU_TIMEOUT\t");
					break;				
				case TAG_MTU_TABLE	:
					printf("TAG_MTU_TABLE\t");
					break;				
				case TAG_INT_MTU	:
					printf("TAG_INT_MTU\t");
					break;				
				case TAG_LOCAL_SUBNETS:
					printf("TAG_LOCAL_SUBNETS\t");
					break;				
				case TAG_BROAD_ADDR	:
					printf("TAG_BROAD_ADDR\t");
					break;				
				case TAG_DO_MASK_DISC:
					printf("TAG_DO_MASK_DISC\t");
					break;				
				case TAG_SUPPLY_MASK	:
					printf("TAG_SUPPLY_MASK\t");
					break;				
				case TAG_DO_RDISC	:
					printf("TAG_DO_RDISC\t");
					break;				
				case TAG_RTR_SOL_ADDR:
					printf("TAG_RTR_SOL_ADDR\t");
					break;				
				case TAG_STATIC_ROUTE:
					printf("TAG_STATIC_ROUTE\t");
					break;				
				case TAG_USE_TRAILERS:
					printf("TAG_USE_TRAILERS\t");
					break;				
				case TAG_ARP_TIMEOUT	:
					printf("TAG_ARP_TIMEOUT\t");
					break;				
				case TAG_ETH_ENCAP	:
					printf("TAG_ETH_ENCAP\t");
					break;				
				case TAG_TCP_TTL	:
					printf("TAG_TCP_TTL\t");
					break;				
				case TAG_TCP_KEEPALIVE:
					printf("TAG_TCP_KEEPALIVE\t");
					break;				
				case TAG_KEEPALIVE_GO:
					printf("TAG_KEEPALIVE_GO\t");
					break;				
				case TAG_NIS_DOMAIN:
					printf("TAG_NIS_DOMAIN\t");
					break;				
				case TAG_NIS_SERVERS	:
					printf("TAG_NIS_SERVERS\t");
					break;				
				case TAG_NTP_SERVERS	:
					printf("TAG_NTP_SERVERS\t");
					break;				
				case TAG_VENDOR_OPTS	:
					printf("TAG_VENDOR_OPTS\t");
					break;				
				case TAG_NETBIOS_NS	:
					printf("TAG_NETBIOS_NS\t");
					break;				
				case TAG_NETBIOS_DDS	:
					printf("TAG_NETBIOS_DDS\t");
					break;				
				case TAG_NETBIOS_NODE:
					printf("TAG_NETBIOS_NODE\t");
					break;				
				case TAG_NETBIOS_SCOPE:
					printf("TAG_NETBIOS_SCOPE\t");
					break;				
				case TAG_XWIN_FS	:
					printf("TAG_XWIN_FS\t");
					break;				
				case TAG_XWIN_DM	:
					printf("TAG_XWIN_DM\t");
					break;				
				case TAG_NIS_P_DOMAIN:
					printf("TAG_NIS_P_DOMAIN\t");
					break;				
				case TAG_NIS_P_SERVERS:
					printf("TAG_NIS_P_SERVERS\t");
					break;				
				case TAG_MOBILE_HOME	:
					printf("TAG_MOBILE_HOME\t");
					break;				
				case TAG_SMPT_SERVER	:
					printf("TAG_SMPT_SERVER\t");
					break;				
				case TAG_POP3_SERVER	:
					printf("TAG_POP3_SERVER\t");
					break;				
				case TAG_NNTP_SERVER	:
					printf("TAG_NNTP_SERVER\t");
					break;				
				case TAG_WWW_SERVER	:
					printf("TAG_WWW_SERVER\t");
					break;				
				case TAG_FINGER_SERVER:
					printf("TAG_FINGER_SERVER\t");
					break;				
				case TAG_IRC_SERVER	:
					printf("TAG_IRC_SERVER\t");
					break;				
				case TAG_STREETTALK_SRVR:
					printf("TAG_STREETTALK_SRVR\t");
					break;				
				case TAG_STREETTALK_STDA:
					printf("TAG_STREETTALK_STDA\t");
					break;/* DHCP options */
				
				case TAG_REQUESTED_IP:
					printf("TAG_REQUESTED_IP\t");
					break;				
				case TAG_IP_LEASE	:
					printf("TAG_IP_LEASE\t");
					break;				
				case TAG_OPT_OVERLOAD:
					printf("TAG_OPT_OVERLOAD\t");
					break;				
				case TAG_TFTP_SERVER	:
					printf("TAG_TFTP_SERVER\t");
					break;				
				case TAG_BOOTFILENAME:
					printf("TAG_BOOTFILENAME\t");
					break;				
				case TAG_DHCP_MESSAGE:
					break;				
				case TAG_SERVER_ID	:
					printf("TAG_SERVER_ID\t");
					break;				
				case TAG_PARM_REQUEST:
					printf("TAG_PARM_REQUEST\t");
					break;				
				case TAG_MESSAGE	:
					printf("TAG_MESSAGE\t");
					break;				
				case TAG_MAX_MSG_SIZE:
					printf("TAG_MAX_MSG_SIZE\t");
					break;				
				case TAG_RENEWAL_TIME:
					printf("TAG_RENEWAL_TIME\t");
					break;				
				case TAG_REBIND_TIME	:
					printf("TAG_REBIND_TIME\t");
					break;				
				case TAG_VENDOR_CLASS:
					printf("TAG_VENDOR_CLASS\t");
					break;				
				case TAG_CLIENT_ID	:
					printf("TAG_CLIENT_ID\t");
					break;/* RFC 2241 */
				
				case TAG_NDS_SERVERS	:
					printf("TAG_NDS_SERVERS\t");
					break;				
				case TAG_NDS_TREE_NAME:
					printf("TAG_NDS_TREE_NAME\t");
					break;				
				case TAG_NDS_CONTEXT	:
					printf("TAG_NDS_CONTEXT\t");
					break;/* RFC 2242 */
				
				case TAG_NDS_IPDOMAIN:
					printf("TAG_NDS_IPDOMAIN\t");
					break;				
				case TAG_NDS_IPINFO	:
					printf("TAG_NDS_IPINFO\t");
					break;/* RFC 2485 */
				
				case TAG_OPEN_GROUP_UAP:
					printf("TAG_OPEN_GROUP_UAP\t");
					break;/* RFC 2563 */
				
				case TAG_DISABLE_AUTOCONF:
					printf("TAG_DISABLE_AUTOCONF\t");
					break;/* RFC 2610 */
				
				case TAG_SLP_DA	:
					printf("TAG_SLP_DA\t");
					break;				
				case TAG_SLP_SCOPE	:
					printf("TAG_SLP_SCOPE\t");
					break;/* RFC 2937 */
				
				case TAG_NS_SEARCH	:
					printf("TAG_NS_SEARCH\t");
					break;/* RFC 3011 */
				
				case TAG_IP4_SUBNET_SELECT:
					printf("TAG_IP4_SUBNET_SELECT\t");
					break;/* ftp://ftp.isi.edu/.../assignments/bootp-dhcp-extensions */
				
				case TAG_USER_CLASS	:
					printf("TAG_USER_CLASS\t");
					break;				
				case TAG_SLP_NAMING_AUTH:
					printf("TAG_SLP_NAMING_AUTH\t");
					break;				
				case TAG_CLIENT_FQDN	:
					printf("TAG_CLIENT_FQDN\t");
					break;				
				case TAG_AGENT_CIRCUIT:
					printf("TAG_AGENT_CIRCUIT\t");
					break;				
				case TAG_AGENT_REMOTE:
					printf("TAG_AGENT_REMOTE\t");
					break;				
				case TAG_AGENT_MASK	:
					printf("TAG_AGENT_MASK\t");
					break;				
				case TAG_TZ_STRING	:
					printf("TAG_TZ_STRING\t");
					break;				
				case TAG_FQDN_OPTION	:
					printf("TAG_FQDN_OPTION\t");
					break;				
				case TAG_AUTH	:
					printf("TAG_AUTH\t");
					break;				
				case TAG_VINES_SERVERS:
					printf("TAG_VINES_SERVERS\t");
					break;				
				case TAG_SERVER_RANK	:
					printf("TAG_SERVER_RANK\t");
					break;				
				case TAG_CLIENT_ARCH	:
					printf("TAG_CLIENT_ARCH\t");
					break;				
				case TAG_CLIENT_NDI	:
					printf("TAG_CLIENT_NDI\t");
					break;				
				case TAG_CLIENT_GUID	:
					printf("TAG_CLIENT_GUID\t");
					break;				
				case TAG_LDAP_URL	:
					printf("TAG_LDAP_URL\t");
					break;				
				case TAG_6OVER4	:
					printf("TAG_6OVER4\t");
					break;				
				case TAG_PRINTER_NAME:
					printf("TAG_PRINTER_NAME\t");
					break;				
				case TAG_MDHCP_SERVER:
					printf("TAG_MDHCP_SERVER\t");
					break;				
				case TAG_IPX_COMPAT	:
					printf("TAG_IPX_COMPAT\t");
					break;				
				case TAG_NETINFO_PARENT:
					printf("TAG_NETINFO_PARENT\t");
					break;				
				case TAG_NETINFO_PARENT_TAG:
					printf("TAG_NETINFO_PARENT_TAG\t");
					break;				
				case TAG_URL:
					printf("TAG_URL\t");
					break;				
				case TAG_FAILOVER	:
					printf("TAG_FAILOVER\t");
					break;				
				case TAG_EXTENDED_REQUEST:
					printf("TAG_EXTENDED_REQUEST\t");
					break;				
				case TAG_EXTENDED_OPTION:
					printf("TAG_EXTENDED_OPTION\t");
					break;
				default:
					printf("Unknow (%d)\t", type);
					break;
			}

			longueur = bytes[n+1];
			printf("L:%d\t", longueur);
			
			printf("V:");
			int *valeur = malloc(longueur*sizeof(int));
			for( i = 0; i < longueur ; i++ ){
				valeur[i] = bytes[n+2+i];
				printf("%d ", valeur[i]);
			}

			if ( type == TAG_DHCP_MESSAGE)
			{
				switch(valeur[0]){
					case DHCPDISCOVER:
						printf(" DHCPDISCOVER ");
						break;
					case DHCPOFFER:
						printf(" DHCPOFFER ");
						break;
					case DHCPREQUEST:
						printf(" DHCPREQUEST ");
						break;
					case DHCPDECLINE:
						printf(" DHCPDECLINE ");
						break;
					case DHCPACK :
						printf(" DHCPACK ");
						break;
					case DHCPNAK :
						printf(" DHCPNAK ");
						break;
					case DHCPRELEASE :
						printf(" DHCPRELEASE ");
						break;
					case DHCPINFORM :
						printf(" DHCPINFORM ");
						break;
					default:
						printf(" Unknow %d\n", valeur[0]);
						break;
				}
			}
			printf("\n");
			free(valeur);
			type = bytes[n+2+longueur];
			n += 1;
		}
	}
	else{
		printf("\t Vendor magic field is %d.%d.%d.%d\n", bootp->bp_vend[0], bootp->bp_vend[1], bootp->bp_vend[2], bootp->bp_vend[3]);
	}

	switch(bootp->bp_op){
		case BOOTREPLY:
			printf("\n");
	}

}

void analyse_bootp(User *user, const u_char *bytes){

	Bootp *bootp = malloc(sizeof(Bootp));

	bootp = (Bootp *)bytes;

	affichage_bootp(user, bootp, bytes);

}