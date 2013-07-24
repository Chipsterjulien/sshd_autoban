# -*- coding: utf-8 -*-

"""
"""

import os

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
                with open(obj.open_file, 'w') as target:
                    target.write(obj.data)
