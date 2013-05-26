Sshd_autoban
============

I wrote this script for fun and learn python 3. This script look ssh log
("journalctl", syslog-ng or rsyslog). It connect with a local socket.
This script can ban agressors with iptables, shorewall or hosts.deny
(actually) and it' efficient with fast and slow brute force attack.
It send abuse mail with whois command and regexp


Depends
=======

yaml-python


Installation
============

```
git clone https://github.com/Chipsterjulien/sshd_autoban.git
python setup.py install
```


Usage
=====
```
python sshd_autoban -h
```



License
=======
<a href="http://en.wikipedia.org/wiki/Gplv3#Version_3">GPL v3</a>
