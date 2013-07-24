# -*- coding: utf-8 -*-

######################################################################
# Copyright (C) 2013 Julien Freyermuth
# All Rights Reserved
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
######################################################################


__author__           = "Julien Freyermuth"
__author_email__     = "julien [dote] chipster [hate] gmail [dote] com"
__copyright__        = "Copyright (c) 2013, Julien Freyermuth"
__description__      = "A ssh autoban for fast and slow brute force attack"
__long_description__ = "I wrote this script for fun and learn python 3. This  \
                script look ssh log (\"journalctl\", syslog-ng or rsyslog). It  \
                connect with a local socket. This script can ban agressors with  \
                iptables, shorewall or hosts.deny (actually) and it's efficient  \
                with fast and slow brute force attack. It send abuse mail with whois  \
                command and regexp"
__license__          = "GPLv3"
__name__             = "sshd_autoban"
__platforms__        = "GNU/Linux"
__url__              = "https://github.com/Chipsterjulien/sshd_autoban"
__version__          = '0.3.1'
__version_info__     = (0, 3, 1, '', 0)


from .banfunc import banfunc
from .check_ip_process import check_ip_process
from .clean_process import clean_process
from .init_connection import init_connection
from .ip import Ip
from .load_banned_ip import load_banned_ip
from .mylog import *
from .read_conf_file import read_conf_file
from .read_write_process import read_write_process
from .thing import Thing
