.. _quickstart:

Quick start guide
=================

Here's a complete example ``fabfile.py``::

    # -*- coding: utf-8 -*-
    """fabfile.py -- Fabric file for a matrioshka deployment.
    """
    from fabric.api import *
    from matrioshka.goulash import *

    env.roledefs.update({
        'web': ['www1.mydomain.com', 'www2.mydomain.com'],
        'db': ['db1.mydomain.com'],
        'ci': ['ci.mydomain.com'],
        'monitor': ['guardian.mydomain.com'],
        })

    # Define system packages, by role, to be installed by apt-get.
    env.system_packages = {
        'all': [
            'emacs23-nox',
            'htop',
            'screen',
            'multitail',
            'git-core',
            'python-dev',
            'python-setuptools',
            'python-psycopg2',
            'munin-node',
            'libnet-cidr-perl',
            ],
        'web': [
            'nginx',
            'libxml2',
            'libxml2-dev',
            'libxslt1.1',
            'libxslt1-dev',
            ],
        'db': [
            'postgresql',
            ],
        'ci': [
            'nginx',
            'jenkins',
            'pylint',
            ],
        'monitor': [
            'munin',
            ],
        }
    
    # Define python packages, by role, to be installed by pip.
    env.python_packages = {
        'all': [
            'virtualenv',
            'paver',
           ],
        }


    # Define pre- and post- hooks for any of: 
    #     roles, system packages, python packages.
    @post('web')
    def web_post():
       run('echo Do stuff on all the web role hosts here.')


    @post('nginx')
    def nginx_post():
        run('echo Do stuff every time nginx is installed.')

    @post('munin-node')
    @only_for('db')
    def db_munin_node_post():
        run('echo Do stuff every time munin-node is installed on a db role.')


    # Define firewall rules (optional) to send to UFW, the default ubuntu firewall.
    env.firewalls = dict(
        # Shell commands start with $
        # UFW commands do not.
        all = [
            '$ yes|sudo ufw reset',
            '$ rm /etc/ufw/*.rules.*',
            'default deny',
            'logging on',
            'allow ssh',
            '$ yes|sudo ufw enable',
            'delete allow ssh',
            ],
        web = [
            'allow http',
            ],
        ci = [
            'allow http',
            ],
        db_master = [
            ],
        )
