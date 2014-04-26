# -*- coding:utf-8 -*-

"""
"""

import os
import socket


def load_banned_ip(cfg, ban_file):
    # On récupère les adresses ip bannies
    if not os.path.exists(ban_file):
        return

    hash_ip = dict()
    src     = open(ban_file, 'r')
    lines   = src.readlines()
    src.close()

    lines = [line.rstrip('\n') for line in lines]

    for line in lines:
        if line == '':
            continue

        ip, hour = line.split(' ')

        if ip in hash_ip:
            # Si on connait déjà l'IP
            hash_ip[ip] = max(hash_ip[ip], float(hour))

        else:
            # Si elle n'est pas déjà présente, on l'ajoute dans le dico
            hash_ip[ip] = float(hour)

    # On bannit toutes les ip se trouvant dans le fichier
    for ip in hash_ip.keys():
        # Si l'adresse ip fait partie de la liste blanche, on passe à l'adresse suivante
        if ip in cfg['authorised ip']:
            continue

        # On bannit l'IP
        os.system('iptables -I INPUT -s {0} -d {1} -j DROP'.format(ip, socket.gethostbyname(socket.gethostname())))
