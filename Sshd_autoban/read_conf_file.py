# -*- coding: utf-8 -*-

"""
"""

import sys
import yaml

from Sshd_autoban.mylog import logging


def read_conf_file(conf):
    data = str()

    try:
        # On charge le fichier de configuration
        file_yaml = open(conf, 'r')
        # On lit le fichier de configuration avec la méthode safe
        data = yaml.safe_load(file_yaml.read())
        # On ferme le fichier
        file_yaml.close()

    # Une exception est levée s'il y a un problème à la lecture
    except yaml.parser.ParserError as e:
        logging.critical("Unable to load configuration. Mistake : \"{0}\"\nVerify you have start systemd-journal-gatewayd.service".format(e))
        sys.exit(2)

    # Si aucune donnée n'a été lu, on arrête le programme
    if not data:
        logging.critical("\"{0}\" is an empty file !".format(conf))
        sys.exit(2)

    return data
