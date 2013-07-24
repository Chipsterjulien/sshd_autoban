# -*- coding: utf-8 -*-

"""
"""

import socket
import sys

from Sshd_autoban.mylog import logging


def init_connection(cfg):
    # Permet de stocker l'objet socket
    sock = None

    try:
        # Définition de la socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        logging.critical("Unable to create socket : {0}".format(e))
        sys.exit(2)

    try:
        # Connection
        sock.connect((cfg['listen ip'], cfg['listen port']))
    except socket.error as e:
        logging.critical("Unable to connect at {0} on port {1} : {2}".format(cfg['listen ip'], cfg['listen port'], str(e)))
        sys.exit(2)

    return sock
