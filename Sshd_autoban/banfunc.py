# -*- coding: utf-8 -*-

"""
This function ban IP who is passed in parameters
"""

import os
import socket
import time

from Sshd_autoban.thing import Thing
from Sshd_autoban.mylog import logging


def banfunc(lock, cfg, ban_file, the_ip, rwqueue, check_queue):
    with lock:
        rwqueue.put(Thing(open_file=ban_file, check_process=True, read=True))

    f      = check_queue.get()
    tab_ip = []

    for line in f:
        if line == '':
            continue

        tab_ip.append(line.split(' ')[0])

        # Si l'IP a déjà été bannie, on relache le verrou et on ne fait rien
        # d'autre
        if the_ip in tab_ip:
            return

    if cfg['ban type'] == 'iptables':
        os.system('iptables -I INPUT -s {0} -d {1} -j  \
                  DROP'.format(the_ip,
                               socket.gethostbyname(socket.gethostname())))

    elif cfg['ban type'] == 'hosts':
        string = "ALL: " + the_ip + "\n"
        with lock:
            rwqueue.put(Thing(open_file='/etc/hosts.deny', read=False,
                              data=string))

    elif cfg['ban type'] == 'shorewall':
        os.system("shorewall drop {0} && shorewall save".format(the_ip))

    # On enregistre l'IP avec l'heure à laquelle on l'a banni
    string = the_ip + " " + str(time.time()).split('.')[0] + "\n"
    with lock:
        rwqueue.put(Thing(open_file=ban_file, check_process=True, read=False,
                          data=string))

    # On écrit dans le log
    logging.warning(the_ip + " banned !")

    # On envoie un mail sur l'abuse
    os.system("/usr/bin/mailer_python {0}".format(the_ip))
