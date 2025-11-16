// Sniffer réseau en C (libpcap)

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// Fonction appelée à chaque paquet capturé
void traiter_paquet(u_char *args, const struct pcap_pkthdr *entete, const u_char *donnees) {
    const struct ip *entete_ip;
    entete_ip = (struct ip*)(donnees + 14); // 14 = entête Ethernet

    char adresse_source[INET_ADDRSTRLEN];
    char adresse_destination[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(entete_ip->ip_src), adresse_source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(entete_ip->ip_dst), adresse_destination, INET_ADDRSTRLEN);

    printf("\n--- Nouveau paquet ---\n");
    printf("Taille du paquet : %d octets\n", entete->len);
    printf("Source : %s\n", adresse_source);
    printf("Destination : %s\n", adresse_destination);

    // Détection du protocole
    switch (entete_ip->ip_p) {
        case IPPROTO_TCP:
            printf("Protocole : TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Protocole : UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("Protocole : ICMP\n");
            break;
        default:
            printf("Protocole : Inconnu (%d)\n", entete_ip->ip_p);
            break;
    }
}

int main() {
    char erreur[PCAP_ERRBUF_SIZE];
    char *interface_reseau;

    // Récupération de l'interface par défaut
    interface_reseau = pcap_lookupdev(erreur);
    if (interface_reseau == NULL) {
        printf("Erreur : impossible de trouver l'interface (%s)\n", erreur);
        return 1;
    }

    printf("Interface utilisée : %s\n", interface_reseau);

    pcap_t *descripteur_capture = pcap_open_live(interface_reseau, 65535, 1, 0, erreur);
    if (descripteur_capture == NULL) {
        printf("Erreur d'ouverture : %s\n", erreur);
        return 1;
    }

    printf("Sniffer en cours... Appuyez sur CTRL+C pour arrêter.\n");

    // Lancement de la capture (boucle infinie)
    pcap_loop(descripteur_capture, -1, traiter_paquet, NULL);

    pcap_close(descripteur_capture);
    return 0;
}



