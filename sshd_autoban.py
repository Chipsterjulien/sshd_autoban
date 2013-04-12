#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
# - sshd_autoban.py - v0.3 -
# ** Changelog
#
#    v0.3 - Add a separate process to read/write file. Solve strange bugs
#
#    v0.2 - Resolve a bug in load banned list of ip
#         - Remove potential duplicate ip in the banned list
#         - Remove a bug when I split time.time()
#         - Adding the possibility of read systemd, syslog-ng and rsyslog
#         - Adding 3 methods of ban: hosts.deny, iptables & shorewall
#         - Adding cleanup fonction
#         - Adding mail script to send abuse mail
#         - Using multiprocess
#
#    v0.1 - Create this script
# **




from multiprocessing import Process, Lock, Queue
import socket, sys, logging, os, yaml, re, time




class Ip():
	def __init__(self):
		self.first_time = time.time()
		self.time       = self.first_time
		self.number     = 1
		self.counter    = 1

	def set_number(self):
		self.time     = time.time()
		self.number  += 1
		self.counter += 1

	def reset_number(self):
		self.time     = time.time()
		self.number   = 1
		self.counter += 1




class Thing():
	def __init__(self, open_file=None, check_process=bool(), read=bool(), data=str(), add=True):
		self.open_file = open_file
		self.check     = check_process
		self.data      = data
		self.read      = read
		self.add       = add



def banfunc(lock, cfg, ban_file, the_ip, rwqueue, check_queue):
	with lock:
		rwqueue.put(Thing(open_file=ban_file, check_process=True, read=True))

	f      = check_queue.get()
	tab_ip = []

	for line in f:
		if line == '':
			continue

		tab_ip.append(line.split(' ')[0])

		# Si l'IP a déjà été bannie, on relache le verrou et on ne fait rien d'autre
		if the_ip in tab_ip:
			return

	if cfg['ban type'] == 'iptables':
		os.system('iptables -I INPUT -s %s -d %s -j DROP' %(the_ip, socket.gethostbyname(socket.gethostname())))

	elif cfg['ban type'] == 'hosts':
		string = "ALL: " + the_ip + "\n"
		with lock:
			rwqueue.put(objThing(open_file='/etc/hosts.deny', read=False, data=string))

	elif cfg['ban type'] == 'shorewall':
		os.system("shorewall drop %s && shorewall save" %(the_ip))

	# On enregistre l'IP avec l'heure à laquelle on l'a banni
	string = the_ip + " " + str(time.time()).split('.')[0] + "\n"
	with lock:
		rwqueue.put(Thing(open_file=ban_file, check_process=True, read=False, data=string))

	# On écrit dans le log
	logging.warning(the_ip + " banned !")

	# On envoie un mail sur l'abuse
	os.system("/usr/bin/mailer_python %s" %(the_ip))




def check_ip_process(lock, cfg, ban_file, sock, rwqueue, check_queue):
	loop     = True # Permet ou non de quitter la boucle
	data     = None # Permet de récupérer les données par le serveur
	string   = ""   # Chaine qui va permettre de découper data correctement
	dic_ip   = {}   # Dictionnaire contenant les IP flashées mais pas encore bannies
	ip_regex = re.compile(r'(([\d]+\.){3}[\d]+)') # Expression régulière pour trouver les IP

	while loop:
		try:
			# On récupère les données sur la socket
			data = sock.recv(4096)
		except socket.timeout:
			logging.critical("Timeout")
			loop = False

		# Si data est nul c'est que la connexion a été coupée
		if not data:
			loop = False
		# Si la taille est négative, c'est qu'il y a eu une erreur de lecture
		if len(data) < 0:
			logging.critical("Misreading !")
			sys.exit(2)

		# On parcourt toutes les lettres reçues
		for letter in data.decode('utf8', 'ignore'):
			# Si la lettre correspond à '\r', on ne fait rien
			if letter == '\r':
				continue

			# Si la lettre correspond à '\n', on a reçu une ligne complète
			elif letter == '\n':
				if len(string) == 0:
					continue

				# Si la chaine n'est pas vide, on va la traiter
				else:
					# On parcourt toutes les erreurs listées
					for err in cfg['error']:
						# Si l'erreur en court fait partie de la chaine
						if err in string:
							# On récupère l'adresse IP de la chaine
							res = ip_regex.search(string)
							if res:
								# On stocke cette adresse
								the_ip = res.group(1)

								# Si l'IP fait partie des adresses à ne pas bannir, on ne va pas plus loin
								if the_ip in cfg['authorised ip']:
									# On l'indique quand même dans les logs
									logging.warning('The user identified by the ip address %s gave a wrong password !' %(the_ip))
									break

								# Si l'IP existe dans le dictionnaire des IP déjà flashées
								if the_ip in dic_ip.keys():
									# On détermine le temps depuis la dernière erreur
									diff = time.time() - dic_ip[the_ip].time

									# Si cela fait moins de 15s on augmente le compteur de 1
									if diff <= cfg['max second']:
										dic_ip[the_ip].set_number()

									# Autrement on remet le compteur à 1 pour éviter de bannir des faux positifs
									else:
										dic_ip[the_ip].reset_number()

									# On vérifie si la personne a dépassé le quota total pour les attaques avec des délais important entre les essais
									if dic_ip[the_ip].counter >= cfg['max attempts by day']:
										# On vérifie si c'est inférieur ou égal à 1 jour
										if dic_ip[the_ip].time - dic_ip[the_ip].first_time <= (3600 * 24):
											banfunc(lock, cfg, ban_file, the_ip, rwqueue, check_queue)

											# On supprime la clef du dictionnaire puisque l'on vient de la bannir
											del(dic_ip[the_ip])

										else:
											# On réinitialise counter à 1
											dic_ip[the_ip].counter = 1
											# On réinitialise l'heure du premier flash
											dic_ip[the_ip].first_time = time.time()

									# Sinon on vérifie si elle a dépassé le nombre d'essais dans un laps de temps
									elif dic_ip[the_ip].number >= cfg['attempts']:
										banfunc(lock, cfg, ban_file, the_ip, rwqueue, check_queue)

										# On supprime la clef du dictionnaire
										del(dic_ip[the_ip])

								# Si l'IP n'existe pas dans le dictionnaire
								else:
									# On rajoute l'IP
									dic_ip[the_ip] = Ip()

							# Vu que l'on a pris l'IP pour cette erreur, pas besoin de chercher avec les autres
							break

				# On réinitialise la chaine de départ
				string = ""

			# La chaine n'est pas une ligne finie
			else:
				# On ajoute le lettre à la fin de la chaine existante
				string += letter

	# On ferme la connexion avec le serveur
	sock.close()




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
		print("Unknown cleanup period in config file !")
		logging.critical("Unknown cleanup period in config file !")
		sys.exit(2)

	while loop:
		with lock:
			rwqueue.put(Thing(open_file=ban_file, check_process=False, read=False))

		hash_ip  = {}
		f        = clean_queue.get()

		for line in f:
			if line == '':
				continue

			ip, hour = line.split(' ')
			hash_ip[ip] = float(hour)

		new_hash = {}
		string   = str()
		now      = time.time()                   # On récupère l'heure

		if cfg['ban type'] == 'iptables':
			for ip, hour in hash_ip.items():
				if hour + period < now:
					os.system('iptables -D INPUT -s %s -d %s -j DROP' %(ip, socket.gethostbyname(socket.gethostname())))
				else:
					new_hash[ip] = hour
					string += str(ip) + ' ' + str(hour) + '\n'

		elif cfg['ban type'] == 'hosts':
			string2 = str()
			for ip, hour in hash_ip.items():
				if hour + period > now:
					new_hash[ip] = hour
					string  += str(ip) + ' ' + str(hour) + '\n'
					string2 += "ALL: " + str(ip) + ' #'+ str(hour) + '\n'

			with lock:
				rwqueue.put(Thing(open_file='/etc/hosts.deny', check_process=False, read=False, add=False, data=string2))

		elif cfg['ban type'] == 'shorewall':
			for ip, hour in hash_ip.items():
				if hour + period < now:
					os.system('shorewall allow %s' %(ip))
				else:
					new_hash[ip] = hour
					string  += str(ip) + ' ' + str(hour) + '\n'

			os.system('shorewall save')

			with lock:
				rwqueue.put(Thing(open_file=ban_file, check_process=False, read=False, add=False, data=string))

		# On s'endort
		try:
			time.sleep(min([(val + period) - now for val in new_hash.values()]))
		except ValueError:
			time.sleep(period)




def init_connection(cfg):
	sock = None # Permet de stocker l'objet socket

	try:
		# Définition de la socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error as e:
		print("Unable to create socket : %s" %(e))
		logging.critical("Unable to create socket : %s" %(e))
		sys.exit(2)

	try:
		# Connection
		sock.connect((cfg['listen ip'], cfg['listen port']))
	except socket.error as e:
		print("Unable to connect at %s on port %s : %s" %(cfg['listen ip'], cfg['listen port'], str(e)))
		logging.critical("Unable to connect at %s on port %s : %s" %(cfg['listen ip'], cfg['listen port'], str(e)))
		sys.exit(2)

	return sock




def load_banned_ip(cfg, ban_file):
	# On récupère les adresses ip bannies
	if not os.path.exists(ban_file):
		return

	hash_ip = dict()
	src     = open(ban_file, 'r')
	lines   = src.readlines()
	src.close()

	lines = [line.rstrip('\n') for line in lines]

	for line in lines:
		if line == '':
			continue

		ip, hour = line.split(' ')
		
		if ip in hash_ip:
			# Si on connait déjà l'IP
			hash_ip[ip] = max(hash_ip[ip], float(hour))

		else:
			# Si elle n'est pas déjà présente, on l'ajoute dans le dico
			hash_ip[ip] = float(hour)

	# On bannit toutes les ip se trouvant dans le fichier
	for ip in hash_ip.keys():
		# Si l'adresse ip fait partie de la liste blanche, on passe à l'adresse suivante
		if ip in cfg['authorised ip']:
			continue

		# On bannit l'IP
		os.system('iptables -I INPUT -s %s -d %s -j DROP' %(ip, socket.gethostbyname(socket.gethostname())))




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
		print("Unable to load configuration. Mistake : \"%s\"\nVerify you have start systemd-journal-gatewayd.service" %(e))
		logging.critical("Unable to load configuration. Mistake : \"%s\"\nVerify you have start systemd-journal-gatewayd.service" %(e))
		sys.exit(2)

	# Si aucune donnée n'a été lu, on arrête le programme
	if not data:
		print("\"%s\" is an empty file !" % (conf))
		logging.critical("\"%s\" is an empty file !" %(conf))
		sys.exit(2)

	return data




def read_write_process(lock, rwqueue, check_queue, clean_queue):
	while 1:
		obj = rwqueue.get()
		# Si read = True c'est que l'on fait de la lecture
		if obj.read:
			if os.path.exists(obj.open_file):
				src = open(obj.open_file, 'r')
				f   = src.readlines()
				src.close()

				# On enlève les \n de fin de ligne
				f = [line.rstrip('\n') for line in f]

				if obj.check:
					check_queue.put(f)

				else:
					clean_queue.put(f)

			else:
				if obj.check:
					check_queue.put(list())

				else:
					clean_queue.put(list())

		# Sinon c'est que l'on fait de l'écriture
		else:
			if obj.add:
				with open(obj.open_file, 'a') as target:
					target.write(obj.data)

			else:
				with open(obj.open_file, 'r') as target:
					target.write(obj.data)




if __name__ == "__main__":
	ban_file  = "/var/log/sshd_autoban/banned_ip"
	conf_file = "/etc/sshd_autoban/sshd_autoban.conf"
	log_file  = "/var/log/sshd_autoban/main.log"
	logging.basicConfig(filename=log_file, format='%(asctime)s %(message)s', level=logging.INFO)

	lock        = Lock()
	rwqueue     = Queue()
	check_queue = Queue()
	clean_queue = Queue()

	logging.info("\n*** Starting logs analysis ***\n\n")

	# On regarde si le fichier de configuration existe
	if not os.path.exists(conf_file):
		print("File \"%s\" not found !" %(conf_file))
		logging.critical("File \"%s\" not found !" %(conf_file))
		sys.exit(2)

	# On charge la configuration
	conf = read_conf_file(conf_file)

	if conf['ban type'] == 'iptables':
		# On rebannie les adresses IP qui sont toujours dans ban_file
		load_banned_ip(conf, ban_file)

	# On initialise la connexion
	sock = init_connection(conf)

	# Si le system est configurer pour utiliser journalctl
	if conf['system'] == 'journalctl':
		# On envoie un message à journalctl
		sock.send("GET /entries?boot&follow HTTP/1.1\r\n\r\n".encode('ascii'))

	# Lancement des processus parallélisés
	Process(target=read_write_process, args=(lock, rwqueue, check_queue, clean_queue)).start()
	Process(target=check_ip_process, args=(lock, conf, ban_file, sock, rwqueue, check_queue)).start()
	if conf['cleanup period'] != 'never':
		Process(target=clean_process, args=(lock, conf, ban_file, rwqueue, clean_queue)).start()
