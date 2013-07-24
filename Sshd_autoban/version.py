# -*- coding: utf-8 -*-

"""
Sshd_autoban: A ssh autoban for fast and slow brute force attack
Copyright (C) 2013 Julien Freyermuth
All Rights Reserved
This file is part of sshd_autoban.

See the file LICENSE for copying permission.
"""

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
__version__          = '0.3.0'
__version_info__     = (0, 3, 0, '', 0)


AUTHOR           = __author__
AUTHOR_EMAIL     = __author_email__
COPYRIGHT        = __copyright__
DESCRIPTION      = __description__
LONG_DESCRIPTION = __long_description__
LICENSE          = __license__
NAME             = __name__
PLATFORMS        = __platforms__
URL              = __url__
VERSION          = __version__
VERSION_INFO     = __version_info__
