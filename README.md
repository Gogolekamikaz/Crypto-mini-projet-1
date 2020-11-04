# Crypto-mini-projet-1

Bonjour, nous créons ce fichier pour vous informer des bonus que nous avons choisi d'effectuer, dans le cadre du mini projet, ainsi que sa notice d'utilisation.

##                                                                      CHANGEMENTS

                                                   | Interface Utilisateur en console : fichier UI.java | 

Demande à l'utilisateur s'il veut chiffrer, déchiffrer un message et lui propose en fonction un panel de méthodes de chiffrement/déchiffrement en adéquation avec ce qu'il convenait de faire pour le MP1.


                                                    | Chiffrement Vigenère Avancé : dans Decrypt.java |

Pour palier au manque de précision de l'algorithme de déchiffrement par fréquence Vigenère, nous avons décidé d'ajouter cette méthode. Elle permet de gérer un plus grand nombre de cas, notamment pour ce qui est de la taille de la clé (il est possible de trouver une clé comportant jusqu'à 100 caractères), mais aussi par rapport à la langue du message codé : 5 langues sont ainsi disponibles (Anglais, Français, Allemand, Italien, Espagnol).

     => Pour ce faire, on applique un algorithme "Brute-force" qui testera les différentes tailles de clé pour tous les langages et choisira le message qui a le plus de sens par rapport au dictionnaire.


                                                                 | Autres Changements |
                                                                 
D'autres changements personnels ont été fait dans les différents fichiers du projet dont :
    * Helper.java - Ajout d'une méthode de lecture des fichiers dictionnaires (celle permettant de préciser le chemin d'accès)
    * Encrypt.java et Decrypt.java - Ajout de méthodes de surcharge pour traiter tous les cas, changement des imports...

##                                                                       NOTICE
