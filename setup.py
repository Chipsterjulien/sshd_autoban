#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sshd_autoban: A ssh autoban for fast and slow brute force attack
Copyright (C) 2013 Julien Freyermuth
All Rights Reserved
This file is part of Sshd_autoban.

See the file LICENSE for copying permission.
"""


#------
# Used http://www.python.org/dev/peps/pep-0314/ and
# http://getpython3.com/diveintopython3/packaging.html
#
# https://pypi.python.org/pypi?%3Aaction=list_classifiers
#
# to wrote this script
#------------------------


try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved',
    'Natural Language :: English',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 3',
    'Topic :: Internet',
]


DATA_FILES = [('/etc/sshd_autoban', ['cfg/sshd_autoban.conf']),
              ('/usr/lib/systemd/system', ['cfg/sshd_autoban.service'])]
              
SCRIPTS = ['sshd_autoban', ]


setup(
    name             = 'sshd_autoban',
    version          = '0.4',
    description      = 'A ssh autoban for fast and slow brute force attack',
    long_description = "I wrote this script for fun and learn python 3. This  \
                script look ssh log (\"journalctl\", syslog-ng or rsyslog). It \
                connect with a local socket. This script can ban agressors with \
                iptables, shorewall or hosts.deny (actually) and it's efficient \
                with fast and slow brute force attack. It send abuse mail with \
                whois command and regexp",
    author           = 'Freyermuth Julien',
    author_email     = 'julien [dote] chipster [hate] gmail [dote] com',
    url              = 'https://github.com/Chipsterjulien/sshd_autoban',
    license          = 'WTFPL',
    platforms        = 'GNU/Linux',
    data_files       = DATA_FILES,
    packages         = find_packages(),
    include_package_data = True,
    scripts          = SCRIPTS,
    requires         = ['python (>=3.4)'],
    classifiers      = CLASSIFIERS,
)
