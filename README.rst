Sshd_autoban
============

I wrote this script for fun and learn python 3. This script look ssh log
("journalctl", syslog-ng or rsyslog). It connect with a local socket.
This script can ban agressors with iptables, shorewall or hosts.deny
(actually) and it efficient with fast and slow brute force attack.
It send abuse mail with whois command and regexp


Depends
=======

python 3


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
