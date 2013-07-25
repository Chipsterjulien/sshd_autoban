# -*- coding: utf-8 -*-

"""
This function enable the sock with log server
"""

import socket
import sys

from Sshd_autoban.mylog import logger


def init_connection(cfg):
    # Permet de stocker l'objet socket
    sock = None

    try:
        # Définition de la socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        logger.critical("Unable to create socket : {0}".format(e))
        sys.exit(1)

    try:
        # Connection
        sock.connect((cfg['listen ip'], cfg['listen port']))
    except socket.error as e:
        logger.critical("Unable to connect at {0} on port {1} : {2}".format(cfg['listen ip'], cfg['listen port'], str(e)))
        sys.exit(1)

    return sock
