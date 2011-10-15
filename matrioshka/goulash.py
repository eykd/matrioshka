# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Project   : Goulash - Functions to write Fabric recipies, based on Cuisine
# -----------------------------------------------------------------------------
# Author    : Sebastien Pierre                            <sebastien@ffctn.com>
# Author    : Thierry Stiegler   (gentoo port)     <thierry.stiegler@gmail.com>
# Author    : Jim McCoy (distro checks and rpm port)      <jim.mccoy@gmail.com>
# Author    : David Eyk (ported to new project, matrioshka.goulash)
# License   : Revised BSD License
# -----------------------------------------------------------------------------
# Creation  : 26-Apr-2010
# Ported    : 07-Oct-2011
# -----------------------------------------------------------------------------
"""
    Goulash
    ~~~~~~~

    ``goulash`` makes it easy to write automatic server installation and
    configuration recipies by wrapping common administrative tasks
    (installing packages, creating users and groups) in Python functions.

    ``goulash`` is designed to work with Fabric and provide all you need
    for getting your new server up and running in minutes.

    Note, that right now, Goulash only supports Debian-based Linux systems.

    Goulash is derived from Cuisine, by Sebastien Pierre, et al.

    .. seealso::

       `Deploying Django with Fabric
       <http://lethain.com/entry/2008/nov/04/deploying-django-with-fabric>`_

       `Notes on Python Fabric 0.9b1
       <http://www.saltycrane.com/blog/2009/10/notes-python-fabric-09b1>`_

       `EC2, fabric, and "err: stdin: is not a tty"
       <http://blog.markfeeney.com/2009/12/ec2-fabric-and-err-stdin-is-not-tty.html>`_

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""
import os
import base64
import bz2
import string
import re
import time
import random
import crypt
import functools
import datetime
import socket
import time

from collections import defaultdict

import fabric
from fabric import api
from fabric import context_managers

from paver.easy import path

VERSION     = "0.0.4"
MODE        = "user"
RE_SPACES   = re.compile("[\s\t]+")
WINDOWS_EOL = "\r\n"
UNIX_EOL    = "\n"
MAC_EOL     = "\n"

api.env.job_queue = []
api.env.system_packages = defaultdict(list)
api.env.python_packages = defaultdict(list)
api.env.firewalls = defaultdict(list)

# Pre-deployment
api.env.on_start = []
# Post-deployment
api.env.on_stop = []

# Environment setup constructors
api.env.prepare = defaultdict(list)
# Pre-package/role constructors
api.env.before = defaultdict(list)
# Post-package/role constructors
api.env.after = defaultdict(list)

api.env.knocks = {}


### Env, Pre, Post decorators.
def on_start(func):
    api.env.on_start.append(func)
    return func


def on_stop(func):
    api.env.on_stop.append(func)
    return func


def prepare(role):
    """Decorates a function to run before any other role events.
    """
    def prepare_decorate(func):
        api.env.prepare[role].append(func)
        return func
    return prepare_decorate


def before(name):
    """Decorates a function to run before the given event.
    """
    def before_decorate(func):
        api.env.before[name].append(func)
        return func
    return before_decorate


def after(name):
    """Decorates a function to run after the given event.
    """
    def after_decorate(func):
        api.env.after[name].append(func)
        return func
    return after_decorate


def only_for(*roles):
    """Decorates a function to only run for the specified roles.
    """
    roles = set()
    for role in roles:
        roles.update(role.split())

    def only_decorate(func):
        @functools.wraps(func)
        def run_if_in_role(*args, **kwargs):
            if api.env.role_string in roles:
                return func(*args, **kwargs)

        return run_if_in_role

    return only_decorate


### Usermode helpers
class mode_user(object):
    def __init__(self):
        global MODE
        self._old_mode = MODE
        MODE = "user"

    def __enter__(self):
        pass

    def __exit__(self, *args, **kws):
        global MODE
        MODE = self._old_mode


class mode_sudo(object):
    def __init__(self):
        global MODE
        self._old_mode = MODE
        MODE = "sudo"

    def __enter__(self):
        pass

    def __exit__(self, *args, **kws):
        global MODE
        MODE = self._old_mode

        
### Enhancements to fabri.api 
def run(*args, **kwargs):
    """A wrapper to Fabric's run/sudo commands, using the 'goulash.MODE' global
    to tell wether the command should be run as regular user or sudo."""
    if MODE == "sudo":
        return api.sudo(*args, **kwargs)
    else:
        return api.run(*args, **kwargs)


def sudo(*args, **kwargs):
    """A wrapper to Fabric's run/sudo commands, using the 'goulash.MODE' global
    to tell wether the command should be run as regular user or sudo."""
    return api.sudo(*args, **kwargs)


### Helpers and decorators
def multiargs(function):
    """Decorated functions will be 'map'ed to every element of the first argument
    if it is a list or a tuple, otherwise the function will execute normally."""
    def wrapper(*args, **kwargs):
        if len(args) == 0:
            return function()
        arg = args[0]
        args = args[1:]
        if type(arg) in (tuple, list):
            return map(lambda _: function(_, *args, **kwargs), arg)
        else:
            return function(arg, *args, **kwargs)
    return wrapper


def text_detect_eol(text):
    # FIXME: Should look at the first line
    if text.find("\r\n") != -1: return WINDOWS_EOL
    elif text.find("\n") != -1: return UNIX_EOL
    elif text.find("\r") != -1: return MAC_EOL
    else: return "\n"


def text_get_line(text, predicate):
    """Returns the first line that matches the given predicate."""
    for line in text.split("\n"):
        if predicate(line):
            return line
    return ""


def text_normalize(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub(" ", text).strip()


def text_nospace(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub("", text).strip()


def text_replace_line(text, old, new, find=lambda old, new: old == new, process=lambda _: _):
    """Replaces lines equal to 'old' with 'new', returning the new text and the
    count of replacements."""
    res      = []
    replaced = 0
    eol      = text_detect_eol(text)
    for line in text.split(eol):
        if find(process(line), process(old)):
            res.append(new)
            replaced += 1
        else:
            res.append(line)
    return eol.join(res), replaced


def text_ensure_line(text, *lines):
    """Ensures that the given lines are present in the given text, otherwise appends the lines
    that are not already in the text at the end of it."""
    eol = text_detect_eol(text)
    res = list(text.split(eol))
    for line in lines:
        assert line.find(eol) == -1, "No EOL allowed in lines parameter: " + repr(line)
        found = False
        for l in res:
            if l == res:
                found = True
                break
        if not found:
            res.append(line)
    return eol.join(res)


def text_strip_margin(text, margin="|"):
    res = []
    eol = text_detect_eol(text)
    for line in text.split(eol):
        l = line.split(margin, 1)
        if len(l) == 2:
            _, line = l
            res.append(line)
    return eol.join(res)


def text_template(text, variables):
    """Substitutes '${PLACEHOLDER}'s within the text with the
    corresponding values from variables."""
    template = string.Template(text)
    return template.safe_substitute(variables)


def local_read(location):
    """Reads a *local* file from the given location, expanding '~' and shell variables."""
    p = os.path.expandvars(os.path.expanduser(location))
    f = file(p, 'rb')
    t = f.read()
    f.close()
    return t


def file_read(location):
    """Reads the *remote* file at the given location."""
    return run("cat '%s'" % (location))


def file_exists(location):
    """Tests if there is a *remote* file at the given location."""
    return run("test -f '%s' && echo OK ; true" % (location)) == "OK"


def file_attribs(location, mode=None, owner=None, group=None, recursive=False):
    """Updates the mode/owner/group for the remote file at the given location."""
    recursive = recursive and "-R " or ""
    if mode: run("chmod %s %s '%s'" % (recursive, mode, location))
    if owner: run("chown %s %s '%s'" % (recursive, owner, location))
    if group: run("chgrp %s %s '%s'" % (recursive, group, location))


def file_write(location, content, mode=None, owner=None, group=None):
    """Writes the given content to the file at the given remote location, optionally
    setting mode/owner/group."""
    # Hides the output, which is especially important
    with context_managers.settings(
        api.hide('warnings', 'running', 'stdout'), 
        warn_only=True
   ):
        # We use bz2 compression
        run("echo '%s' | base64 -d | bzcat > \"%s\"" % (base64.b64encode(bz2.compress(content)), location))
        file_attribs(location, mode, owner, group)


def file_update(location, updater=lambda x: x):
    """Updates the content of the given by passing the existing content of the remote file
    at the given location to the 'updater' function.

    For instance, if you'd like to convert an existing file to all uppercase, simply do:

    >   file_update("/etc/myfile", lambda _: _.upper())
    """
    assert file_exists(location), "File does not exists: " + location
    new_content = updater(file_read(location))
    assert type(new_content) in (str, unicode, fabric.operations._AttributeString) \
    , "Updater must be like (string)->string, got: %s() = %s" % (updater, type(new_content))
    run("echo '%s' | base64 -d > \"%s\"" % (base64.b64encode(new_content), location))


def file_append(location, content, mode=None, owner=None, group=None):
    """Appends the given content to the remote file at the given location, optionally
    updating its mode/owner/group."""
    run("echo '%s' | base64 -d >> \"%s\"" % (base64.b64encode(content), location))
    file_attribs(location, mode, owner, group)


def dir_attribs(location, mode=None, owner=None, group=None, recursive=False):
    """Updates the mode/owner/group for the given remote directory."""
    file_attribs(location, mode, owner, group, recursive)


def dir_exists(location):
    """Tells if there is a remote directory at the given location."""
    return run("test -d '%s' && echo OK ; true" % (location)).endswith("OK")


def dir_ensure(location, recursive=False, mode=None, owner=None, group=None):
    """Ensures that there is a remote directory at the given location, optionnaly
    updating its mode/owner/group.

    If we are not updating the owner/group then this can be done as a single
    ssh call, so use that method, otherwise set owner/group after creation."""
    if mode:
        mode_arg = "-m %s" % (mode)
    else:
        mode_arg = ""
    run("test -d '%s' || mkdir %s %s '%s' && echo OK ; true" % (location, recursive and "-p" or "", mode_arg, location))
    if owner or group:
        dir_attribs(location, owner=owner, group=group)


def command_check(command):
    """Tests if the given command is available on the system."""
    return run("which '%s' >& /dev/null && echo OK ; true" % command).endswith("OK")


def package_update(package=None):
    """Updates the package database (when no argument) or update the package
    or list of packages given as argument."""
    if package == None:
        sudo("apt-get --yes update")
    else:
        if type(package) in (list, tuple): package = " ".join(package)
        sudo("apt-get --yes upgrade " + package)


def package_install(package, update=False):
    """Installs the given package/list of package, optionnaly updating the package
    database."""
    if update: sudo("apt-get --yes update")
    if type(package) in (list, tuple): package = " ".join(package)
    sudo("apt-get --yes install %s" % (package))


@multiargs
def package_ensure(package):
    """Tests if the given package is installed, and installes it in case it's not
    already there."""
    if run("dpkg-query -W -f='${Status}' %s ; true" % package).find("installed") == -1:
        package_install(package)


def command_ensure(command, package=None):
    """Ensures that the given command is present, if not installs the package with the given
    name, which is the same as the command by default."""
    if package is None: package = command
    if not command_check(command): package_install(package)
    assert command_check(command), "Command was not installed, check for errors: %s" % (command)


def user_create(name, passwd=None, home=None, uid=None, gid=None, shell=None, uid_min=None, uid_max=None):
    """Creates the user with the given name, optionally giving a specific password/home/uid/gid/shell."""
    options = ["-m"]
    if passwd:
        method = 6
        saltchars = string.ascii_letters + string.digits + './'
        salt = ''.join([random.choice(saltchars) for x in range(8)])
        passwd_crypted = crypt.crypt(passwd, '$%s$%s' % (method, salt))
        options.append("-p '%s'" % (passwd_crypted))
    if home: options.append("-d '%s'" % (home))
    if uid: options.append("-u '%s'" % (uid))
    if gid: options.append("-g '%s'" % (gid))
    if shell: options.append("-s '%s'" % (shell))
    if uid_min: options.append("-K UID_MIN='%s'" % (uid_min))
    if uid_max: options.append("-K UID_MAX='%s'" % (uid_max))
    sudo("useradd %s '%s'" % (" ".join(options), name))


def user_check(name):
    """Checks if there is a user defined with the given name, returning its information
    as a '{"name": <str>, "uid": <str>, "gid": <str>, "home": <str>, "shell": <str>}' or 'None' if
    the user does not exists."""
    d = sudo("cat /etc/passwd | egrep '^%s:' ; true" % (name))
    s = sudo("cat /etc/shadow | egrep '^%s:' | awk -F':' '{print $2}'" % (name))
    results = {}
    if d:
        d = d.split(":")
        results = dict(name=d[0], uid=d[2], gid=d[3], home=d[5], shell=d[6])
    if s:
        results['passwd']=s
    if results:
        return results
    else:
        return None


def user_ensure(name, passwd=None, home=None, uid=None, gid=None, shell=None):
    """Ensures that the given users exists, optionally updating their passwd/home/uid/gid/shell."""
    d = user_check(name)
    if not d:
        user_create(name, passwd, home, uid, gid, shell)
    else:
        options=[]
        if passwd != None and d.get('passwd') != None:
            method, salt = d.get('passwd').split('$')[1:3]
            passwd_crypted = crypt.crypt(passwd, '$%s$%s' % (method, salt))
            if passwd_crypted != d.get('passwd'):
                options.append("-p '%s'" % (passwd_crypted))
        if passwd != None and d.get('passwd') is None:
            # user doesn't have passwd
            method = 6
            saltchars = string.ascii_letters + string.digits + './'
            salt = ''.join([random.choice(saltchars) for x in range(8)])
            passwd_crypted = crypt.crypt(passwd, '$%s$%s' % (method, salt))
            options.append("-p '%s'" % (passwd_crypted))
        if home != None and d.get("home") != home:
            options.append("-d '%s'" % (home))
        if uid  != None and d.get("uid") != uid:
            options.append("-u '%s'" % (uid))
        if gid  != None and d.get("gid") != gid:
            options.append("-g '%s'" % (gid))
        if shell != None and d.get("shell") != shell:
            options.append("-s '%s'" % (shell))
        if options:
            sudo("usermod %s '%s'" % (" ".join(options), name))


def group_create(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""
    options = []
    if gid: options.append("-g '%s'" % (gid))
    sudo("groupadd %s '%s'" % (" ".join(options), name))


def group_check(name):
    """Checks if there is a group defined with the given name, returning its information
    as a '{"name": <str>, "gid": <str>, "members": <list[str]>}' or 'None' if the group
    does not exists."""
    group_data = run("cat /etc/group | egrep '^%s:' ; true" % (name))
    if group_data:
        name, _, gid, members = group_data.split(":", 4)
        return dict(name=name, gid=gid, members=tuple(m.strip() for m in members.split(", ")))
    else:
        return None


def group_ensure(name, gid=None):
    """Ensures that the group with the given name (and optional gid) exists."""
    d = group_check(name)
    if not d:
        group_create(name, gid)
    else:
        if gid != None and d.get("gid") != gid:
            sudo("groupmod -g %s '%s'" % (gid, name))


def group_user_check(group, user):
    """Checks if the given user is a member of the given group. It will return 'False'
    if the group does not exist."""
    d = group_check(group)
    if d is None:
        return False
    else:
        return user in d["members"]


@multiargs
def group_user_add(group, user):
    """Adds the given user/list of users to the given group/groups."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if not group_user_check(group, user):
        sudo("usermod -a -G '%s' '%s'" % (group, user))


def group_user_ensure(group, user):
    """Ensure that a given user is a member of a given group."""
    d = group_check(group)
    if user not in d["members"]:
        group_user_add(group, user)


def ssh_keygen(user, keytype="dsa"):
    """Generates a pair of ssh keys in the user's home .ssh directory."""
    d = user_check(user)
    assert d, "User does not exist: %s" % (user)
    home = d["home"]
    if not file_exists(home + "/.ssh/id_%s.pub" % keytype):
        dir_ensure(home + "/.ssh", mode="0700", owner=user, group=user)
        run("ssh-keygen -q -t %s -f '%s/.ssh/id_%s' -N ''" % (keytype, home, keytype))
        file_attribs(home + "/.ssh/id_%s" % keytype, owner=user, group=user)
        file_attribs(home + "/.ssh/id_%s.pub" % keytype, owner=user, group=user)


def ssh_authorize(user, key):
    """Adds the given key to the '.ssh/authorized_keys' for the given user."""
    d    = user_check(user)
    keyf = d["home"] + "/.ssh/authorized_keys"
    if file_exists(keyf):
                file_update(keyf, lambda _: text_ensure_line(_, key))
    else:
        file_write(keyf, key, owner=user, group=user)


def upstart_ensure(name, restart=False):
    """Ensures that the given upstart service is running, restarting it if necessary"""
    if sudo("status "+ name).find("/running") >= 0:
        if restart:
            if not isinstance(restart, basestring):
                restart = 'restart'
            sudo("%s %s" % (restart, name))
    else:
        sudo("start " + name)


def service_ensure(name, restart=False):
    """Ensures that the given init.d service is running, restarting it if necessary
    """
    with api.settings(warn_only = True):
        if sudo("service %s status" % name, combine_stderr=True).find("running") >= 0:
            if restart:
                if not isinstance(restart, basestring):
                    restart = 'restart'
                sudo("service %s %s" % (name, restart))
        else:
            sudo("service %s start" % name)


def file_copy(target_on_server, local_path,
              mode_target=None, mode=None, owner=None, group=None):
    sudo('cp %s %s' % (local_path, target_on_server))
    with mode_sudo():
        file_attribs(target_on_server if mode_target is None else mode_target,
                     mode=mode, owner=owner, group=group)


def ls(where):
    return [(fn, fn.split('/')[-1]) for fn in run('ls %s' % where).split()]


### Operator Notifications
def date(message=None, sticky=False):
    """Notify with a message and date.
    """
    now = datetime.datetime.now()
    notify('%s\n%s' % (now, message if message is not None else ''), sticky=sticky)


def notify(msg, sticky=False):
    """Send a notification.
    """
    with context_managers.settings(warn_only=True):
        api.local("%(notifier)s %(stickyflag)s %(messageflag)s '%(message)s'" % dict(
            notifier = api.env.get('notifier', 'growlnotify'), 
            stickyflag = api.env.get('stickyflag', '-s') if sticky else '', 
            messageflag = api.env.get('messageflag', '-m'), 
            message = msg.replace("'", r"'\''")))


def notifies(sticky=False):
    """Task decorator for sending a notification message on task entry.
    """
    if callable(sticky):
        func = sticky
        sticky = False
    else:
        func = None

    def decorator(func):
        @functools.wraps(func)
        def notify(*args, **kwargs):
            try:
                msg = func.__doc__.split('\n')[0]
            except (AttributeError, IndexError):
                msg = ''
            if args:
                msg = "%s\n%s" % (msg, args)
            if kwargs:
                msg = "%s\n%s" % (msg, kwargs)
            if getattr(api.env, 'role_string', None):
                msg = "Role: %s\n%s" % (api.env.role_string, msg)
            
            date(msg, sticky=sticky)
            return func(*args, **kwargs)

        return notify

    if func is not None:
        return decorator(func)
    else:
        return decorator


### Job queue managers
def enqueue(priority, func, *args, **kwargs):
    api.env.job_queue.append((priority, func, args, kwargs))


def run_queued():
    api.env.job_queue.sort()
    for priority, func, args, kwargs in api.env.job_queue:
        func(*args, **dict(kwargs))
    api.env.job_queue[:] = ()


def enable_nginx_site(site, source):
    mode_sudo()
    file_write('/etc/nginx/sites-available/%s' % site, path(source).text(),
               mode=644, owner='root', group='root')
    if file_exists('/etc/nginx/sites-enabled/%s' % site):
        sudo('rm /etc/nginx/sites-enabled/%s' % site)
    sudo('ln -s /etc/nginx/sites-available/%(site)s /etc/nginx/sites-enabled/%(site)s' % {'site': site})
    mode_user()
    enqueue(100, sudo, '/etc/init.d/nginx reload')


def enable_munin_plugin(plugin):
    mode_sudo()
    if file_exists('/etc/munin/plugins/%s' % plugin):
        sudo('rm /etc/munin/plugins/%s' % plugin)
    sudo('ln -s /usr/share/munin/plugins/%(plugin)s /etc/munin/plugins/%(plugin)s' % {'plugin': plugin})
    mode_user()


@api.task
def knock(host, *ports):
    """Knock on servers to open up ssh.
    """
    for port in ports:
        #create an INET, STREAMing socket
        print "Knocking on", host, port
        try:
            s = socket.socket(proto=socket.SOL_TCP)
            s.settimeout(1)
            s.connect((host, int(port)))
        except socket.timeout:
            print "Knock..."
        time.sleep(1)
    

### Main Deploy task
@api.task
@notifies
def deploy(**kwargs):
    """Deploy the specified roles.
    """
    if kwargs:
        for role, host in kwargs.iteritems():
            api.env.roledefs[role] = [host]
    api.env.roledefs['all'] = list(set(host for hosts in api.env.roledefs.itervalues() for host in hosts))
    # default to all roles.
    if not api.env.roles:
        api.env.roles = list(api.env.roledefs.keys())

    # Move 'all' to the front of the list.
    api.env.roles.sort(lambda a, b: -1 if a == 'all' else cmp(a, b))
    notify('Deploying to %s.'% ', '.join(api.env.roles), sticky=False)

    for start in api.env.on_start:
        start()

    for role in api.env.roles:
        print "###########################################"
        print "##### Role:", role
        print "###########################################"
        print "###########################################"
        api.env.role_string = role

        notify('Deploying to role %s' % role, sticky=False)

        for host in api.env.roledefs[api.env.role_string]:
            ## local('paver knock -t {host} -p {knocks}'.format(
            ##     host = host, knocks = ','.join(site['KNOCKS']['ssh'])
            ##     ))
            notify('Deploying to %s as role %s' % (host, role), sticky=False)

            if host in api.env.knocks:
                knock(host, *api.env.knocks[host])

            with api.settings(host_string=host):
                for p in api.env.prepare[api.env.role_string]:
                    p()
                    
                for p in api.env.before[api.env.role_string]:
                    p()

                install_system_packages()
                install_python_packages()

                for p in api.env.after[api.env.role_string]:
                    p()

                apply_firewall()

                run_queued()

    for stop in api.env.on_stop:
        stop()

    notify('Deployed to %s.\nDone.' % ', '.join(api.env.roles), sticky=False)


### Deploy helpers
@notifies
def install_system_packages():
    """Install system packages.
    """
    package_update()
    packages = api.env.system_packages.get(api.env.role_string, ())
    for package in packages:
        for p in api.env.before[package]:
            p()

    if packages:
        package_install(packages)

    for package in packages:
        for p in api.env.after[package]:
            p()


@notifies
def install_python_packages():
    """Install systemwide python packages.
    """
    packages = ' '.join(api.env.python_packages.get(api.env.role_string, ()))
    if packages:
        sudo('pip install %s' % packages)


@notifies
def apply_firewall():
    """Apply firewall rules.
    """
    if command_check('ufw'):
        firewalls = api.env.firewalls[api.env.role_string]
        for command in firewalls:
            if command.startswith('$'):
                sudo(command[1:])
            else:
                sudo('ufw %s' % command)
        if firewalls:
            sudo('ufw reload')
