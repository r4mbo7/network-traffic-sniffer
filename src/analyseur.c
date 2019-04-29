/**
 * @file      analyseur.c
 * @author    De La Roche Constantin
 * @version   1
 * @date      16/12/16
 * @brief     Fonctions principales.
 * @details   Contient tout ce qui concerne pcap
 */

#include "analyseur.h"

/**
 * @brief Constructeur de liste de paquet
 * @details Ajout un paquet à la liste des paquets lus. Utilisé pour l'affichage avec clutter.
 * 
 * @param l Liste des paquets
 * @param nvelt Paquet à ajouter à la liste
 * 
 * @return La liste augmentée.
 */
Liste cons(Liste l, Paquet *nvelt){
	Liste p;
	p = malloc(sizeof(struct maillon));
	p->donnee = nvelt;// <=> *p.donnee=nvelt;
	p->suivant = l;
	return(p);
}

/**
 * @brief Fonction de callback appelé à chaque lecture d'un nouveau paquet.
 * @details Le contenue du paquet contenu dans bytes est forward à la fonction analyse_ethenert qui analyse l'entête ethernet.
 * On crée un nouveau paquet.
 * On met à jour la liste des paquets lus.
 * On met à jour le pointeur user
 * 
 * @param user Véhicule les informations
 * @param pcap_pkthdr Unused
 * @param bytes Contenu du paquet
 */
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){

	time_t intps = time(NULL);
	Date *cur_date = localtime(&intps);
	//printf("Current date : sec : %d\n", cur_date->tm_sec);

	((User *)user)->nb_paquet += 1;

	Paquet *p = malloc(sizeof(struct paquet));
	p->num = ((User *)user)->nb_paquet;
	p->len = h->len;
	p->date = cur_date;
	
	//on ajoute le paquet à la list des paquets
	((User *)user)->l_paquet = cons(((User *)user)->l_paquet, p);

	/*On ne rafraichie clutter que toute les secondes
	if(((User *)user)->opt->v == 0 && ((User *)user)->date_sec_last_paquet != cur_date->tm_sec){
		refresh_menu_actor(((User *)user));
		((User *)user)->date_sec_last_paquet = cur_date->tm_sec;
	}
	*/

	//On commence l'analyse du paquet avec la partie ethernet
	analyse_ethernet((User *)user, bytes);
	printf("\n");
}

/**
 * @brief Affiche les options et les arguments passés à l'exécutable
 * 
 * @param opt Contient les options
 */
void affichage_option(Option *opt){
	printf("-- PARAMS --\nVerbosité : ");
	switch(opt->v){
		case 1:
			printf("Très consis\n");
			break;
		case 2:
			printf("Synthétique\n");
			break;
		case 3:
			printf("Complet\n");
			break;
		default :
			printf(" v=%d\n", opt->v);
			break;
	}
	if(opt->o != NULL){
		printf("Fichier  : %s\n", opt->o);
	}
	if(opt->i != NULL){
		printf("Interface  : %s\n", opt->i);
	}
	else{
		printf("Problème initialisation interface.\n");
	}
	if(opt->f != NULL){
		printf("Filtre  : %s\n", opt->f);
	}
	printf("---\n\n");
}

/**
 * @brief Reconnais les options passés à l'exécutable
 * @details Reconnais et initialise les options passés en argument à l'exécutable.
 * 
 * @param option Pointeur qui contiendra les options
 * @param argc main
 * @param argv main
 */
void set_option(Option *option, int argc, char *argv[]){
	int opt;
	option->i = NULL;
	option->o = NULL;
	option->f = NULL;
	option->v = 1;
	while((opt=getopt(argc, argv, "i:o:f:v:")) != -1){
		switch(opt){
			case 'i':
				option->i = optarg;
				break;
			case 'o':
				option->o = optarg;
				break;
			case 'f':
				option->f = optarg;
				break;
			case 'v':
				option->v = atoi(optarg);
				if(option->v < 1 || option->v > 3){
					option->v = 1;
				}
				break;
			default:
				fprintf(stderr, "Usage ./analyseur -i <Interface> -o <Fichier> -f <Filtre> -v <Verbose 1..3>");
				exit(EXIT_FAILURE);
		}
	}

	/* Define the device */
	if(option->i == NULL){
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		char *dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "SET OPTION : Couldn't find default device (%s)\n", errbuf);
			exit(EXIT_FAILURE);
		}
		option->i = strdup(dev);
	}
}

/**
 * @brief Lance l'analyse en mode online.
 * @details Capture en temps réel
 * 
 * @param user
 */
void start_analyse_online(User *user){

	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char *filter_exp = user->opt->f;	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	
	/* Define the device */
	if(user->opt->i != NULL){
		dev = user->opt->i;
	}
	else{
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* Grab packets*/
	int r;
	if((r = pcap_loop(handle, 0, callback, (u_char *)user)) < 0){
		fprintf(stderr, "Pcap loop error %d\n", r);
	}

	pcap_close(handle);
}

/**
 * @brief Lance l'analyse en mode offline
 * @details Capture à partir d'un fichier.
 * 
 * @param user 
 */
void start_analyse_offline(User *user){

	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char *filter_exp = user->opt->f;	/* The filter expression */
	bpf_u_int32 net = 0;		/* Our IP */

	// open capture file for offline processing
	handle = pcap_open_offline(user->opt->o, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", user->opt->o, errbuf);
		exit(EXIT_FAILURE);
	}


	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* Grab packets*/
	int r;
	if((r = pcap_loop(handle, 0, callback, (u_char *)user)) < 0){
		fprintf(stderr, "Pcap loop error %d\n", r);
	}

	pcap_close(handle);
}

/**
 * @brief Libère la mémoire
 * @details Delete la liste des paquets
 * 
 * @param l_paquet Liste des paquets à effacer
 */
void free_l_paquet(Liste l_paquet){
	if(l_paquet != NULL){
		while(l_paquet->suivant != NULL){
			free(l_paquet->donnee);
			l_paquet = l_paquet->suivant;
		}
		free(l_paquet->donnee);
	}
}

int main(int argc, char *argv[])
{
	//On crée le pointeur qui va véhiculer l'info aux différentes fonctions
	User *user = malloc(sizeof(struct User));
	//On crée le pointeur qui va contenir les options
	Option *opt = malloc(sizeof(struct Option));
	//On set le pointeur en fonction des arguements.
	//Cette fonction peut arrêter le programme.
	set_option(opt, argc, argv);
	//On affiche les options
	affichage_option(opt);

	//On initialise le pointeur véhiculant l'info
	user->opt = opt;
	user->l_paquet = NULL;
	user->nb_paquet = 0;

	//Si on a spécifié un fichier d'entré on lance le mode offline, sinon on lance le mode online
	if(opt->o == NULL){
		start_analyse_online(user);
	}
	else{
		start_analyse_offline(user);
	}
	
	//On libère la mémoire.
	free(opt);
	free_l_paquet(user->l_paquet);
	free(user);
	return(0);
}