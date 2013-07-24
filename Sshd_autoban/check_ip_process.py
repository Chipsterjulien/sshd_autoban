# -*- coding: utf-8 -*-

"""
"""

import re
import socket
import sys
import time

from Sshd_autoban.mylog import logging
from Sshd_autoban.ip import Ip
from Sshd_autoban.banfunc import banfunc

def check_ip_process(lock, cfg, ban_file, sock, rwqueue, check_queue):
    loop     = True # Permet ou non de quitter la boucle
    data     = None # Permet de récupérer les données par le serveur
    string   = ""   # Chaine qui va permettre de découper data correctement
    dic_ip   = {}   # Dictionnaire contenant les IP flashées mais pas encore bannies
    ip_regex = re.compile(r'(([\d]+\.){3}[\d]+)') # Expression régulière pour trouver les IP

    while loop:
        try:
            # On récupère les données sur la socket
            data = sock.recv(4096)
        except socket.timeout:
            logging.critical("Timeout")
            loop = False

        # Si data est nul c'est que la connexion a été coupée
        if not data:
            loop = False
        # Si la taille est négative, c'est qu'il y a eu une erreur de lecture
        if len(data) < 0:
            logging.critical("Misreading !")
            sys.exit(2)

        # On parcourt toutes les lettres reçues
        for letter in data.decode('utf8', 'ignore'):
            # Si la lettre correspond à '\r', on ne fait rien
            if letter == '\r':
                continue

            # Si la lettre correspond à '\n', on a reçu une ligne complète
            elif letter == '\n':
                if len(string) == 0:
                    continue

                # Si la chaine n'est pas vide, on va la traiter
                else:
                    # On parcourt toutes les erreurs listées
                    for err in cfg['error']:
                        # Si l'erreur en court fait partie de la chaine
                        if err in string:
                            # On récupère l'adresse IP de la chaine
                            res = ip_regex.search(string)
                            if res:
                                # On stocke cette adresse
                                the_ip = res.group(1)

                                # Si l'IP fait partie des adresses à ne pas
                                # bannir, on ne va pas plus loin
                                if the_ip in cfg['authorised ip']:
                                    # On l'indique quand même dans les logs
                                    logging.warning('The user identified by  \
                                                    the ip address {0} gave  \
                                                    a wrong password ! \
                                                    '.format(the_ip))
                                    break

                                # Si l'IP existe dans le dictionnaire des IP
                                # déjà flashées
                                if the_ip in dic_ip.keys():
                                    # On détermine le temps depuis la dernière
                                    # erreur
                                    diff = time.time() - dic_ip[the_ip].time

                                    # Si cela fait moins de 15s on augmente le
                                    # compteur de 1
                                    if diff <= cfg['max second']:
                                        dic_ip[the_ip].set_number()

                                    # Autrement on remet le compteur à 1 pour
                                    # éviter de bannir des faux positifs
                                    else:
                                        dic_ip[the_ip].reset_number()

                                    # On vérifie si la personne a dépassé le
                                    # quota total pour les attaques avec des
                                    # délais important entre les essais
                                    if dic_ip[the_ip].counter >= cfg['max attempts by day']:
                                        # On vérifie si c'est inférieur ou égal à 1 jour
                                        if dic_ip[the_ip].time - dic_ip[the_ip].first_time <= (3600 * 24):
                                            banfunc(lock, cfg, ban_file, the_ip, rwqueue, check_queue)

                                            # On supprime la clef du dictionnaire puisque l'on vient de la bannir
                                            del(dic_ip[the_ip])

                                        else:
                                            # On réinitialise counter à 1
                                            dic_ip[the_ip].counter = 1
                                            # On réinitialise l'heure du premier flash
                                            dic_ip[the_ip].first_time = time.time()

                                    # Sinon on vérifie si elle a dépassé le nombre d'essais dans un laps de temps
                                    elif dic_ip[the_ip].number >= cfg['attempts']:
                                        banfunc(lock, cfg, ban_file, the_ip, rwqueue, check_queue)

                                        # On supprime la clef du dictionnaire
                                        del(dic_ip[the_ip])

                                # Si l'IP n'existe pas dans le dictionnaire
                                else:
                                    # On rajoute l'IP
                                    dic_ip[the_ip] = Ip()

                            # Vu que l'on a pris l'IP pour cette erreur, pas besoin de chercher avec les autres
                            break

                # On réinitialise la chaine de départ
                string = ""

            # La chaine n'est pas une ligne finie
            else:
                # On ajoute le lettre à la fin de la chaine existante
                string += letter

    # On ferme la connexion avec le serveur
    sock.close()
