# -*- coding: utf-8 -*-

"""
"""


class Thing():
    def __init__(self, open_file=None, check_process=bool(), read=bool(), data=str(), add=True):
        self.open_file = open_file
        self.check     = check_process
        self.data      = data
        self.read      = read
        self.add       = add
