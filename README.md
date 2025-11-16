# Sniffer réseau (C + libpcap)

Ce projet est un sniffer réseau simple écrit en C. Il utilise la bibliothèque libpcap pour capturer les paquets qui transitent sur l'interface réseau et affiche des informations basiques comme les adresses IP source et destination, la taille du paquet et le protocole utilisé.
Ce projet est conçu pour être clair et accessible tout en montrant des compétences en programmation bas niveau et en analyse réseau.

---

## Fonctionnalités

* Capture en direct des paquets réseau
* Lecture et analyse de l'en-tête IP
* Affichage de l'adresse source et de l'adresse destination
* Indication du protocole (TCP, UDP, ICMP)
* Code minimal pour faciliter la compréhension

---

## Installation

Sous Linux (Debian / Ubuntu) :

```
sudo apt install libpcap-dev
```

---

## Compilation

```
gcc sniffer.c -lpcap -o sniffer
```

---

## Utilisation

```
sudo ./sniffer
```

---

## Structure du projet

```
sniffer-reseau/
 ├── sniffer.c
 └── README.md
```

---

## Notes

* Fonctionne uniquement sous Linux
* Nécessite libpcap
* Projet volontairement simple et pédagogique
