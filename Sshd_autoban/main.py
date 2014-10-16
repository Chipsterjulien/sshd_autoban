#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import configparser
import logging
import logging.handlers
import os
import re
import socket
import subprocess
import sys
import time

from multiprocessing import Process, SimpleQueue, Lock


class Ip():
    def __init__(self):
        self.first_time = time.time()
        self.time = self.first_time
        self.number = 1
        self.counter = 1

    def set_number(self):
        self.time = time.time()
        self.number += 1
        self.counter += 1

    def reset_number(self):
        self.time = time.time()
        self.number = 1
        self.counter += 1


class PortOverflow(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return self.reason


class Thing():
    def __init__(self, *args, **kwargs):
        self.open_file = kwargs.get('open_file', None)
        self.check = kwargs.get('check', False)
        self.read = kwargs.get('read', True)
        self.data = kwargs.get('data', str())
        self.mode = kwargs.get('mode', 'a')


def analyze_ip(*args, **kwargs):
    conf_obj = kwargs.get('conf')
    ip_list = kwargs.get('ip', [])
    ip_dict = kwargs.get('ipdict', {})
    ip_banned_queue = kwargs.get('ipbannedqueue', SimpleQueue())
    ban_ip_dict = {}

    ip_banned_list = convert_queue_to_list(queue=ip_banned_queue)
    convert_list_to_queue(queue=ip_banned_queue, iplist=ip_banned_list)

    for ip in ip_list:
        if ip in ip_banned_list:
            continue
        if ip in ip_dict.keys():
            diff = time.time() - ip_dict[ip].time

            if diff <= float(conf_obj['Default']['max seconds']):
                ip_dict[ip].set_number()
            else:
                ip_dict[ip].reset_number()

            if ip_dict[ip].number >= int(conf_obj['Default']['attempts']):
                ban_ip_dict[ip] = 1

            elif ip_dict[ip].counter >= int(conf_obj['Default']
                                                    ['max attempts by day']):
                if ip_dict[ip].time - ip_dict[ip].first_time <= (3600 * 24):
                    ban_ip_dict[ip] = 1
                else:
                    ip_dict[ip].counter = 1
                    ip_dict[ip].first_time = ip_dict[ip].time

        else:
            ip_dict[ip] = Ip()

    return ip_dict, ban_ip_dict.keys()


def ban_ip_hosts(*args, **kwargs):
    flash_ip_list = kwargs.get('fl')
    rw_queue = kwargs.get('rwqueue')

    string = ""
    for ip in flash_ip_list:
        string += "ALL: {0}\n".format(ip)

    rw_queue.put(Thing(open_file="/etc/hosts.deny", read=False, mode='a',
                       data=string))


def ban_ip_iptables(*args, **kwargs):
    conf_obj = kwargs.get('conf')
    flash_ip_list = kwargs.get('fl')

    for ip in flash_ip_list:
        print('iptables -I INPUT -s {0} -d {1} -j DROP'.format(ip,
              conf_obj['Default']['local ip']))
        subprocess.call('iptables -I INPUT -s {0} -d {1} -j DROP'
                        .format(ip, conf_obj['Default']['local ip']),
                        shell=True)


def ban_ip_shorewall(*args, **kwargs):
    flash_ip_list = kwargs.get('fl')

    for ip in flash_ip_list:
        subprocess.call('shorewall drop {0}'.format(ip), shell=True)

    subprocess.call('shorewall save', shell=True)


def ban_some_ip(*args, **kwargs):
    ban_file = kwargs.get('banfile')
    clean_time = kwargs.get('ct')
    conf_obj = kwargs.get('conf')
    ip_dict = kwargs.get('ipdict')
    ip_list = kwargs.get('fl')
    rw_queue = kwargs.get('rwqueue')

    if conf_obj['Default']['ban type'] == 'iptables':
        ban_ip_iptables(*args, **kwargs)
    elif conf_obj['Default']['ban type'] == 'hosts':
        ban_ip_hosts(*args, **kwargs)
    elif conf_obj['Default']['ban type'] == 'shorewall':
        ban_ip_shorewall(*args, **kwargs)

    string = ""
    next_time = time.time() + clean_time[conf_obj['Default']['cleanup period']]
    str_show = "%A, %d/%m/%y %H:%M:%S"
    for ip in ip_list:
        string += "{0} {1} Human: {2}\n".format(ip, next_time,
                                                time.strftime(str_show, time.gmtime(next_time)))

    rw_queue.put(Thing(open_file=ban_file, read=False, mode='a', data=string))

    for ip in ip_list:
        del(ip_dict[ip])

    return ip_dict


def check_file(*args, **kwargs):
    """ Test if file exist, can test some permissions and create empty file.
    """
    fp = kwargs.get('my_file')
    read = kwargs.get('read', False)
    write = kwargs.get('write', False)
    create = kwargs.get('create', False)

    if not os.path.exists(fp):
        if create:
            if os.access(os.path.dirname(fp), os.W_OK):
                with open(fp, 'w'):
                    pass
            else:
                print("You don't have write permissions on \"{0}\" !\
                      ".format(fp), file=sys.stderr)
                sys.exit(2)

        else:
            print("File \"{0}\" don't exist !".format(fp),
                  file=sys.stderr)
            sys.exit(2)

    if read:
        if not os.access(fp, os.R_OK):
            print("You don't have read permissions on \"{0}\" !"
                  .format(fp), file=sys.stderr)
            sys.exit(2)

    if write:
        if not os.access(fp, os.W_OK):
            print("You don't have write permissions on \"{0}\" !"
                  .format(fp), file=sys.stderr)
            sys.exit(2)


def check_ip_process(*args, **kwargs):
    conf_obj = kwargs.get('conf')

    if conf_obj['Default']['system'] == 'syslog':
        check_ip_syslog(*args, **kwargs)

    else:
        check_ip_journalctl(*args, **kwargs)


def check_ip_journalctl(*args, **kwargs):
    ip_banned_queue = kwargs.get('ipbannedqueue')
    data = kwargs.get('data')
    lock = kwargs.get('lck')
    ip_dict = {}

    for line in data.stdout:
        positive_ip = handling_lines(*args,
                                     lines=[line.decode('utf-8', 'ignore').
                                            strip()], **kwargs)
        if len(positive_ip) != 0:
            ip_dict, ban_ip_list = analyze_ip(*args, ip=positive_ip,
                                              ipdict=ip_dict, **kwargs)
            ip_dict = ban_some_ip(*args, fl=ban_ip_list, ipdict=ip_dict,
                                  **kwargs)
            with lock:
                for ip in ban_ip_list:
                    ip_banned_queue.put(ip)

            for ip in ban_ip_list:
                logging.info("{0} was banned".format(ip))

    data.close()


def check_ip_syslog(*args, **kwargs):
    ip_banned_queue = kwargs.get('ipbannedqueue')
    data = kwargs.get('data')
    lock = kwargs.get('lck')
    ip_dict = {}
    string = ''

    while 1:
        lines, string = get_data(*args, string=string, **kwargs)
        positive_ip = handling_lines(*args, lines=lines, **kwargs)
        if len(positive_ip) != 0:
            ip_dict, ban_ip_list = analyze_ip(*args, ip=positive_ip,
                                              ipdict=ip_dict, **kwargs)
            ip_dict = ban_some_ip(*args, fl=ban_ip_list, ipdict=ip_dict,
                                  **kwargs)
            with lock:
                for ip in ban_ip_list:
                    ip_banned_queue.put(ip)

            for ip in ban_ip_list:
                logging.info("{0} was banned".format(ip))

    data.close()


def clean_host_deny(*args, **kwargs):
    ip_list = kwargs.get('ip')
    rw_queue = kwargs.get('rwqueue')
    clean_queue = kwargs.get('cleanqueue')

    rw_queue.put(Thing(open_file='/etc/hosts.deny', check=False, read=True))
    hosts_file = clean_queue.get()
    string = ''

    for line in hosts_file:
        if line == '':
            string += '\n'

        find = False
        for ip in ip_list:
            if ip in line:
                find = True
                break
        if not find:
            string += line + '\n'

    rw_queue.put(Thing(open_file='/etc/hosts.deny', check=False, read=False,
                       data=string, mode='w'))


def clean_process(*args, **kwargs):
    rw_queue = kwargs.get('rwqueue')
    clean_queue = kwargs.get('cleanqueue')
    ban_file = kwargs.get('banfile')
    conf_obj = kwargs.get('conf')
    clean_time = kwargs.get('ct')

    period = clean_time[conf_obj['Default']['cleanup period']]

    while 1:
        rw_queue.put(Thing(open_file=ban_file, check=False, read=True))
        my_file = clean_queue.get()

        now_time = time.time()
        period_list = []
        ip_to_unban = []
        string = ""

        for line in my_file:
            if line != '':
                my_split = line.strip().split(' ')

                ban_time = float()
                try:
                    ban_time = float(my_split[1])
                except ValueError:
                    logging.error("Unable to convert '{0}' into a float in \
'{1}'".format(my_split[1], line))
                    continue

                if now_time < ban_time:
                    period_list.append(ban_time - now_time)
                    string += line + '\n'

                else:
                    ip_to_unban.append(my_split[0])

        unban_ip(*args, ip_list=ip_to_unban, **kwargs)

        rw_queue.put(Thing(open_file=ban_file, check=False, read=False,
                           mode='w', data=string))

        clean_banned_queue(*args, iptounban=ip_to_unban, **kwargs)

        for ip in ip_to_unban:
            logging.info("'{0}' was clear from {1}".format(ip, ban_file))

        try:
            time.sleep(min(period_list))
        except ValueError:
            time.sleep(period)


def clean_banned_queue(*args, **kwargs):
    ip_banned_queue = kwargs.get('ipbannedqueue')
    ip_to_unban = kwargs.get('iptounban')
    lock = kwargs.get('lck')

    with lock:
        ip_list = convert_queue_to_list(queue=ip_banned_queue)
        for ip in ip_to_unban:
            if ip in ip_list:
                ip_list.remove(ip)
        convert_list_to_queue(queue=ip_banned_queue, iplist=ip_list)


def convert_list_to_queue(*args, **kwargs):
    ip_banned_queue = kwargs.get('queue')
    ip_list = kwargs.get('iplist')

    for ip in ip_list:
        ip_banned_queue.put(ip)


def convert_queue_to_list(*args, **kwargs):
    ip_banned_queue = kwargs.get('queue')
    ip_list = []

    while not ip_banned_queue.empty():
        ip_list.append(ip_banned_queue.get())

    return ip_list


def find_local_ip(*args, **kwargs):
    count = 0
    loop = True
    ip = str()

    while(loop):
        a = subprocess.getoutput('ip a | grep --color=auto "[0-9.]\.[0-9.]"| \
                                 awk \'{print $2}\' | cut -f 1 -d / | grep -v \
                                 127.0.0').split('\n')
        if len(a) != 0:
            loop = False
            ip = a[0]
        else:
            if count >= 10:
                logging.critical("Unable to find a correct local ip !\n\
Exiting …")
                sys.exit(2)

            count += 1
            time.sleep(2)

    return ip


def get_data(*args, **kwargs):
    sock = kwargs.get('sock')
    string = kwargs.get('string')
    data = ""
    lines = []

    try:
        data = sock.recv(4096)
    except socket.timeout:
        logging.critical("timeout")
        sys.exit(2)

    if not data:
        logging.info("The server close the connection !")
        sys.exit(2)

    if len(data) < 0:
        logging.critical("Misreading !")
        sys.exit(2)

    for letter in data.decode('utf-8', 'ignore'):
        if letter == '\r':
            continue
        elif letter == '\n':
            if len(string) == 0:
                continue
            else:
                lines.append(string)
                string = ''
        else:
            string += letter

    return lines, string


def get_iptables_info(*args, **kwargs):
    ip = []
    output = subprocess.getoutput("iptables -nL | grep DROP").split("\n")[1:-1]
    for line in output:
        ip.append(line.split()[3])

    return ip


def handling_lines(*args, **kwargs):
    conf_obj = kwargs.get('conf')
    lines = kwargs.get('lines')
    ip_regex = re.compile(r'([0-9]{1,3}\.){3}[0-9]{1,3}')
    whitelisted_ip = [ip.strip() for ip in conf_obj['Default']
                      ['whitelisted ip'].split(',')]
    positive_ip = []

    for line in lines:
        for err in conf_obj['Default']['error'].split(','):
            if err.strip() in line:
                res = ip_regex.search(line)
                if res:
                    ip = res.group(0)
                    if ip in whitelisted_ip:
                        logging.warning('The user identified by the ip \
address {0} gave a wrong password: ({1}) !'.format(ip, line))
                    else:
                        positive_ip.append(ip)

                break

    return positive_ip


def init_getting_data(*args, **kwargs):
    conf_obj = kwargs.get('conf')

    if conf_obj['Default']['system'] == 'syslog':
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        except socket.error as e:
            logging.critical("Unable to create socket : {0}".format(e))
            sys.exit(2)

        try:
            sock.connect((conf_obj['Default']['local ip'],
                         int(conf_obj['Default']['listen port'])))
        except socket.error as e:
            logging.critical("Unable to connect at {0} on port {1} : {2}"
                             .format(conf_obj['Default']['local ip'],
                                     conf_obj['Default']['listen port'],
                                     str(e)))
            sys.exit(2)

        return sock

    else:
        data = subprocess.Popen(['journalctl', '-f', '-u', 'sshd.service',
                                 '--since', 'now'], stdout=subprocess.PIPE)

        return data


def load_banned_ip(*args, **kwargs):
    ban_file = kwargs.get('fp')
    flash_ip_list = []

    with open(ban_file, 'r') as src:
        for line in src:
            flash_ip_list.append(line.split(' ')[0])

    return flash_ip_list


def load_conf(*args, **kwargs):
    conf = configparser.ConfigParser()
    conf.read(kwargs.get('conf'))

    if not conf.sections():
        print("{0} is not valid or is empty file !"
              .format(kwargs.get('conf')), file=sys.stderr)
        sys.exit(2)

    if 'Default' not in conf:
        print('There is not \"Default\" section in conf file: \"{0}\" !\
'.format(kwargs.get('conf')), file=sys.stderr)
        sys.exit(2)

    for i in ['attempts', 'max attempts by day', 'cleanup period',
              'local ip', 'listen port', 'max seconds', 'system',
              'whitelisted ip', 'blacklisted ip', 'error', 'ban type']:
        if i not in conf['Default']:
            print("\"{0}\" is not in conf file (\"{1}\") !"
                  .format(i, kwargs.get('conf')), file=sys.stderr)
            sys.exit(2)

    test_attempts(conf=conf)
    test_max_seconds(conf=conf)
    test_max_attempts_by_day(conf=conf)
    test_ban_type(conf=conf)
    test_cleanup(conf=conf)
    test_port(conf=conf)
    test_system(conf=conf)

    return conf


def log_activity(*args, **kwargs):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s'
                                  )
    file_handler = logging.handlers.RotatingFileHandler(kwargs.get('log'), 'a',
                                                        1000000, 1)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    steam_handler = logging.StreamHandler()
    steam_handler.setLevel(logging.DEBUG)
    logger.addHandler(steam_handler)


def manage_process(*args, **kwargs):
    process_list = kwargs.get('processlist')

    for process in process_list:
        process.start()

    time.sleep(0.1)

    critical_error = False
    while 1:
        for process in process_list:
            if not process.is_alive():
                critical_error = True

        if critical_error:
            for process in process_list:
                if process.is_alive():
                    process.terminate()
            break

        time.sleep(5)


def read_write_process(*args, **kwargs):
    rw_queue = kwargs.get('rwqueue')
    check_queue = kwargs.get('checkqueue')
    clean_queue = kwargs.get('cleanqueue')

    while 1:
        obj = rw_queue.get()

        if obj.read:
            with open(obj.open_file) as src:
                lines = [line.rstrip('\n') for line in src]
                if obj.check:
                    check_queue.put(lines)
                else:
                    clean_queue.put(lines)
        else:
            with open(obj.open_file, obj.mode) as target:
                target.write(obj.data)


def remove_some_ip(*args, **kwargs):
    ip_already_banned = kwargs.get('ipalreadybanned')
    flash_ip_list = kwargs.get('fl')

    for ip in ip_already_banned:
        try:
            flash_ip_list.remove(ip)
        except ValueError:
            logging.warning("'{0}' is not in flash_ip_list".format(ip))

    return flash_ip_list


def test_attempts(*args, **kwargs):
    conf = kwargs.get('conf')

    try:
        int(conf['Default']['attempts'])
    except ValueError:
        logging.critical("Attempts: '{0}' is not a number !"
                         .format(conf['Default']['attempts']))
        sys.exit(2)


def test_ban_type(*args, **kwargs):
    conf = kwargs.get('conf')

    ban_type = ['hosts', 'iptables', 'shorewall']
    if conf['Default']['ban type'] not in ban_type:
        logging.critical("Ban type: '{0}' is not a right entry !"
                         .format(conf['Default']['ban type']))
        sys.exit(2)


def test_cleanup(*args, **kwargs):
    conf = kwargs.get('conf')

    cleanup = ['day', 'week', 'month', 'never']
    if conf['Default']['cleanup period'] not in cleanup:
        logging.critical("Cleanup period: '{0}' is not a right entry !"
                         .format(conf['Default']['cleanup period']))
        sys.exit(2)


def test_local_ip(*args, **kwargs):
    conf = kwargs.get('conf')

    local_ip = conf['Default']['local ip']
    if local_ip != 'auto':
        local_ip = local_ip.split('.')
        true_ip = False
        if len(local_ip) == 4:
            for part in local_ip:
                if part > 254:
                    break
            true_ip = True

        if not true_ip:
            logging.critical("Local ip: '{0}' is not a valid IPv4"
                             .format(conf['Default']['local ip']))
            sys.exit(2)


def test_max_attempts_by_day(*args, **kwargs):
    conf = kwargs.get('conf')

    try:
        int(conf['Default']['max attempts by day'])
    except ValueError:
        logging.critical("Max attempts by day: '{0}' is not a number !"
                         .format(conf['Default']['max attempts by day']))
        sys.exit(2)


def test_max_seconds(*args, **kwargs):
    conf = kwargs.get('conf')

    try:
        int(conf['Default']['max seconds'])
    except ValueError:
        logging.critical("Max seconds: '{0}' is not a number !"
                         .format(conf['Default']['max seconds']))
        sys.exit(2)


def test_port(*args, **kwargs):
    conf = kwargs.get('conf')

    try:
        port = int(conf['Default']['listen port'])
        if port > 65535:
            raise PortOverflow
    except ValueError:
        logging.critical("Listen port: '{0}' is not a number !"
                         .format(conf['Default']['listen port']))
        sys.exit(2)
    except PortOverflow:
        logging.critical("Listen port: '{0}' is not a valid number. It must be\
 lower than 65535 !".format(port))
        sys.exit(2)


def test_system(*args, **kwargs):
    conf = kwargs.get('conf')

    system = ['journalctl', 'syslog']
    if conf['Default']['system'] not in system:
        logging.critical("System: '{0}' is not a right entry !"
                         .format(conf['Default']['system']))
        sys.exit(2)


def unban_ip(*args, **kwargs):
    conf_obj = kwargs.get('conf')
    ip_list = kwargs.get('ip_list')

    if conf_obj['Default']['ban type'] == 'iptables':
        for ip in ip_list:
            subprocess.call("iptables -D INPUT -s {0} -d {1} -j DROP"
                            .format(ip, conf_obj['Default']['local ip']),
                            shell=True)
    elif conf_obj['Default']['ban type'] == 'hosts':
        clean_host_deny(*args, **kwargs)

    elif conf_obj['Default']['ban type'] == 'shorewall':
        for ip in ip_list:
            subprocess.call("shorewall allow {0}".format(ip), shell=True)
        subprocess.call("shorewall save", shell=True)


def main():
    #####################################################################
    # Mettre une variable pour chaque processus pour savoir s'il
    # est en mode sleep ou non pour savoir si on peut kill l'appli
    # correctement
    #####################################################################

    ban_file = "/var/log/sshd_autoban/banned_ip"
    conf_file = '/etc/sshd_autoban/sshd_autoban.conf'
    log_file = '/var/log/sshd_autoban/main.log'
    # ban_file = "/home/julien/Desktop/sshd_autoban/banned_ip"
    # conf_file = '/home/julien/Desktop/sshd_autoban/cfg/sshd_autoban.conf'
    # log_file = '/home/julien/Desktop/sshd_autoban/cfg/main.log'
    # ban_file = "/home/julien/sshd_autoban/banned_ip"
    # conf_file = '/home/julien/sshd_autoban/cfg/sshd_autoban.conf'
    # log_file = '/home/julien/sshd_autoban/cfg/main.log'

    check_file(my_file=ban_file, read=True, write=True, create=True)
    check_file(my_file=conf_file, read=True, write=False, create=False)
    check_file(my_file=log_file, read=True, write=True, create=True)

    rw_queue = SimpleQueue()
    check_queue = SimpleQueue()
    clean_queue = SimpleQueue()
    ip_banned_queue = SimpleQueue()
    lock = Lock()
    process_list = []

    clean_time = {'day': 3600 * 24, 'week': 3600 * 24 * 7,
                  'month': 3600 * 24 * 7 * 4}

    log_activity(log=log_file)

    logging.info('** Starting analysis **\n')

    conf_obj = load_conf(conf=conf_file, ct=clean_time)
    if conf_obj['Default']['local ip'] == 'auto':
        conf_obj['Default']['local ip'] = find_local_ip()

    flash_ip_list = load_banned_ip(fp=ban_file)
    if conf_obj['Default']['ban type'] == 'iptables':
        if len(flash_ip_list) != 0:
            ip_already_banned = get_iptables_info()
            ip_to_ban_list = remove_some_ip(fl=flash_ip_list,
                                            ipalreadybanned=ip_already_banned)
            ban_ip_iptables(fl=ip_to_ban_list, conf=conf_obj)

    convert_list_to_queue(queue=ip_banned_queue, iplist=flash_ip_list)
    del(flash_ip_list)

    data = init_getting_data(conf=conf_obj)

    process_list.append(Process(target=read_write_process, args=(),
                        kwargs={'rwqueue': rw_queue, 'checkqueue': check_queue,
                        'cleanqueue': clean_queue}))

    process_list.append(Process(target=check_ip_process, args=(),
                        kwargs={'conf': conf_obj, 'ct': clean_time,
                                'banfile': ban_file, 'data': data,
                                'rwqueue': rw_queue,
                                'checkqueue': check_queue,
                                'ipbannedqueue': ip_banned_queue,
                                'lck': lock}))

    if conf_obj['Default']['cleanup period'] != 'never':
        process_list.append(Process(target=clean_process, args=(),
                            kwargs={'conf': conf_obj, 'ct': clean_time,
                                    'banfile': ban_file, 'rwqueue': rw_queue,
                                    'cleanqueue': clean_queue,
                                    'ipbannedqueue': ip_banned_queue,
                                    'lck': lock}))

    manage_process(processlist=process_list)


if __name__ == '__main__':
    pass
