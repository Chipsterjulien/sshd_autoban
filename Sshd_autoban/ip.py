# -*- coding: utf-8 -*-

"""
"""


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
