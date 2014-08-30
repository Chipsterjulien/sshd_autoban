#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.sys.path.insert(0, parentdir)

from Sshd_autoban.main import check_file
import pytest


@pytest.fixture
def create_file(request):
    my_file = os.path.join(os.getcwd(), "test_file.txt")
    with open(my_file, 'w'):
        pass

    def end():
        os.unlink(my_file)

    request.addfinalizer(end)


def test_check_file_without_file_n_all_false():
    with pytest.raises(SystemExit):
        check_file(my_file="", read=False, write=False, create=False)


def test_check_file_without_file_read_true_write_false_n_create_false():
    with pytest.raises(SystemExit):
        check_file(my_file="", read=True, write=False, create=False)


def test_check_file_without_file_read_true_write_true_n_create_false():
    with pytest.raises(SystemExit):
        check_file(my_file="", read=True, write=True, create=False)


def test_check_file_without_file_n_all_true():
    with pytest.raises(FileNotFoundError):
        check_file(my_file="", read=True, write=True, create=True)


def test_check_file_with_file_n_all_false(create_file):
    check_file(my_file="test_file.txt", read=False, write=False, create=False)


def test_check_file_with_file_n_read_true_write_false_n_create_false(create_file):
    check_file(my_file="test_file.txt", read=True, write=False, create=False)
    os.chmod("test_file.txt", 0o333)  # lecture: 4 écriture: 2 exe: 1 (4 + 2 + 1)
    with pytest.raises(SystemExit):
        check_file(my_file="test_file.txt", read=True, write=False, create=False)


def test_check_file_with_file_n_read_true_write_true_n_create_false(create_file):
    check_file(my_file="test_file.txt", read=True, write=True, create=False)
    os.chmod("test_file.txt", 0o555)  # lecture: 4 écriture: 2 exe: 1 (4 + 2 + 1)
    with pytest.raises(SystemExit):
        check_file(my_file="test_file.txt", read=True, write=True, create=False)


def test_check_file_with_file_n_all_true():
    check_file(my_file="test_file.txt", read=True, write=True, create=True)
    if not os.path.exists("test_file.txt"):
        assert 0
    os.unlink("test_file.txt")
