# -*- coding: utf-8 -*-

"""
"""

import sys
import time
import os

from Sshd_autoban.mylog import logger
from Sshd_autoban.thing import Thing

def clean_process(lock, cfg, ban_file, rwqueue, clean_queue):
    loop   = True
    period = int()

    if cfg['cleanup period'] == 'day':
        period = 3600 * 24
    elif cfg['cleanup period'] == 'week':
        period = 3600 * 24 * 7
    elif cfg['cleanup period'] == 'month':
        period = 3600 * 24 * 7 * 4
    else:
        logger.warning("Unknown cleanup period in config file !")
        sys.exit(1)

    while loop:
        with lock:
            rwqueue.put(Thing(open_file=ban_file, check_process=False, read=True))

        hash_ip = {}
        f       = clean_queue.get()

        for line in f:
            if line == '':
                continue

            ip, hour    = line.split(' ')
            hash_ip[ip] = float(hour)

        new_hash = {}
        string   = str()
        now      = time.time() # On récupère l'heure

        if cfg['ban type'] == 'iptables':
            for ip, hour in hash_ip.items():
                if hour + period < now:
                    os.system('iptables -D INPUT -s {0} -d {1} -j DROP'.format(ip, socket.gethostbyname(socket.gethostname())))
                else:
                    new_hash[ip] = hour
                    string += str(ip) + ' ' + str(hour) + '\n'

        elif cfg['ban type'] == 'hosts':
            string2 = str()
            for ip, hour in hash_ip.items():
                if hour + period > now:
                    new_hash[ip] = hour
                    string  += str(ip) + ' ' + str(hour) + '\n'
                    string2 += "ALL: " + str(ip) + ' #' + str(hour) + '\n'

            with lock:
                rwqueue.put(Thing(open_file='/etc/hosts.deny', check_process=False, read=False, add=False, data=string2))

        elif cfg['ban type'] == 'shorewall':
            save = False
            for ip, hour in hash_ip.items():
                if hour + period < now:
                    os.system('shorewall allow {0}'.format(ip))
                    save = True
                else:
                    new_hash[ip] = hour
                    string += str(ip) + ' ' + str(hour) + '\n'

            if save:
                os.system('shorewall save')

            with lock:
                rwqueue.put(Thing(open_file=ban_file, check_process=False, read=False, add=False, data=string))

        # On s'endort
        try:
            time.sleep(min([(val + period) - now for val in new_hash.values()]))
        except ValueError:
            time.sleep(period)
