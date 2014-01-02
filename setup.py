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


import Sshd_autoban


CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    'Natural Language :: English',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 3',
    'Topic :: Internet',
]


DATA_FILES = [('/etc/sshd_autoban', ['cfg/sshd_autoban_example.conf']),
              ('/usr/lib/systemd/system', ['cfg/sshd_autoban.service']),
			  ('/var/log/sshd_autoban', ['log/error.log']),]
SCRIPTS = ['sshd_autoban', 'mailer_python']


setup(
    name             = Sshd_autoban.__name__,
    version          = Sshd_autoban.__version__,
    description      = Sshd_autoban.__description__,
    long_description = Sshd_autoban.__long_description__,
    author           = Sshd_autoban.__author__,
    author_email     = Sshd_autoban.__author_email__,
    url              = Sshd_autoban.__url__,
    license          = Sshd_autoban.__license__,
    platforms        = Sshd_autoban.__platforms__,
    data_files       = DATA_FILES,
    packages         = find_packages(),
    include_package_data = True,
    scripts          = SCRIPTS,
    requires         = ['requests', 'pyyaml', 'python (>=3.3)'],
    classifiers      = CLASSIFIERS,
)
