# -*- coding: utf-8 -*-

"""
This function check yaml data
"""

import sys
import yaml

from Sshd_autoban.mylog import logger


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
        logger.critical("Unable to load configuration. Mistake : \"{0}\"\nVerify you have start systemd-journal-gatewayd.service".format(e))
        sys.exit(1)

    # Si aucune donnée n'a été lu, on arrête le programme
    if not data:
        logger.critical("\"{0}\" is an empty file !".format(conf))
        sys.exit(1)

    return data
