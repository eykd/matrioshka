# -*- coding: utf-8 -*-
"""setup.py -- setup file for Matrioshka deployment mother brain.
"""
from setuptools import setup

setup(
    name = "matrioshka",
    packages = ['matrioshka'],
    install_requires = [
        'Fabric',
        'boto',
        'Paved',
        'path.py',
        ],

    zip_safe = False,

    version = "0.1",
    description = "Mother brain for deploying applications with Fabric. Batteries included.",
    author = "David Eyk",
    author_email = "david.eyk@gmail.com",
    url = "http://github.com/eykd/matrioshka",
    #download_url = "http://github.com/eykd/matrioshka",
    long_description = open('README.md').read(),
    )
