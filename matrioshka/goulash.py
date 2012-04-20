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
import logging
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
import contextlib

from collections import defaultdict

import fabric
from fabric import api
from fabric import context_managers

from path import path

logger = logging.getLogger('matrioshka')

VERSION     = "0.0.4"
MODE        = "user"
RE_SPACES   = re.compile("[\s\t]+")
WINDOWS_EOL = "\r\n"
UNIX_EOL    = "\n"
MAC_EOL     = "\r"

api.env.job_queue = []
api.env.system_packages = defaultdict(list)
api.env.python_packages = defaultdict(list)
api.env.firewalls = defaultdict(list)
api.env.role_secrets = {}

# True if `sudo -u` needs a prepending sudo.
api.env.sudo_sudo_u = True

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

api.env.with_tags = set(['all'])
api.env.not_tags = set()
api.env.knocks = {}


### Events
@contextlib.contextmanager
def emit_events(*events):
    """Context manager to run before and after tasks for specified events.
    """
    before_events(*events)
    yield
    after_events(*events)


def before_events(*events):
    """Run before tasks for specified events.
    """
    for event in events:
        logger.info('Running before-%s tasks' % event)
        for p in api.env.before[event]:
            p()


def after_events(*events):
    """Run after tasks for specified events.
    """
    for event in events:
        logger.info('Running: after-%s tasks' % event)
        for p in api.env.after[event]:
            p()


### Env, Pre, Post event decorators.
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
    for_roles = set()
    for role in roles:
        for_roles.update(role.split())

    def only_decorate(func):
        @functools.wraps(func)
        def run_if_in_role(*args, **kwargs):
            if api.env.role_string in for_roles:
                return func(*args, **kwargs)

        return run_if_in_role

    return only_decorate


def only_on(*roles):
    """Decorates a function to only run on the specified hosts.
    """
    for_roles = set()
    for role in roles:
        for_roles.update(role.split())

    def only_decorate(func):
        @functools.wraps(func)
        def run_if_in_role(*args, **kwargs):
            if api.env.role_string in for_roles:
                return func(*args, **kwargs)

        return run_if_in_role

    return only_decorate


### Usermode helpers
class mode_user(object):
    def __init__(self):
        global MODE
        if MODE == 'suppress':
            self.suppressed = True
        else:
            self.suppressed = False
            self._old_mode = MODE
            MODE = "user"

    def __enter__(self):
        pass

    def __exit__(self, *args, **kws):
        if not self.suppressed:
            global MODE
            MODE = self._old_mode


class mode_sudo(object):
    def __init__(self):
        global MODE
        if MODE == 'suppress':
            self.suppressed = True
        else:
            self.suppressed = False
            self._old_mode = MODE
            MODE = "sudo"

    def __enter__(self):
        pass

    def __exit__(self, *args, **kws):
        if not self.suppressed:
            global MODE
            MODE = self._old_mode


class mode_suppress(object):
    def __init__(self):
        global MODE
        self._old_mode = MODE
        MODE = "suppress"

    def __enter__(self):
        pass

    def __exit__(self, *args, **kws):
        global MODE
        MODE = self._old_mode


# Tags
@contextlib.contextmanager
def tag(*names):
    tags = set(names)
    if ('all' in api.env.with_tags or tags.intersection(api.env.with_tags)) \
           and not tags.intersection(api.env.not_tags):
        logger.info('-------> BEGINNING of tagged section: %s', ', '.join(tags))
        yield
        logger.info('<------- END of tagged section: %s', ', '.join(tags))
    else:
        logger.warning('-------> NOT executing tagged section: (%s) does not intersect (%s):', ', '.join(tags), ', '.join(api.env.with_tags))
        with mode_suppress():
            try:
                yield
            except (AssertionError, TypeError):
                pass
        # logger.warning('<------- RESUMING normal command execution.')
        
        
### Enhancements to fabri.api 
def run(*args, **kwargs):
    """A wrapper to Fabric's run/sudo commands, using the 'goulash.MODE' global
    to tell wether the command should be run as regular user or sudo."""
    if MODE == "suppress":
        return ""
    elif MODE == "sudo":
        return api.sudo(*args, **kwargs)
    else:
        return api.run(*args, **kwargs)


def sudo(*args, **kwargs):
    """A wrapper to Fabric's run/sudo commands, using the 'goulash.MODE' global
    to tell wether the command should be run as regular user or sudo."""
    if MODE == "suppress":
        return ""
    else:
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
        if type(arg) in (tuple, list, set):
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
    for ensure_line in lines:
        assert ensure_line.find(eol) == -1, "No EOL allowed in lines parameter: " + repr(ensure_line)
        found = False
        for line in res:
            if line == ensure_line:
                found = True
                break
        if not found:
            res.append(ensure_line)
    return eol.join(res)


def file_ensure_line(filename, *lines):
    if file_exists(filename):
        file_update(filename, lambda _: text_ensure_line(_, *lines))


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
    return '\n'.join(run("cat '%s'" % (location)).split('\r\n'))


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


def git_config(user, email, name, global_config=True):
    sudo('git config %suser.email "%s"' % ('--global ' if global_config else '', email), user=user)
    sudo('git config %suser.name "%s"' % ('--global ' if global_config else '', name), user=user)


def git_ensure_repo(location, remote, commit_id, as_user, as_user_email=None, as_user_name=None,
                    force=False, update_submodules=False):
    with mode_sudo():
        dir_ensure(location, owner=as_user)
    with api.cd(location):
        with tag('git', 'checkout'):
            if not dir_exists('%s/.git' % location):
                sudo('git init', user=as_user)
            if as_user_email is not None:
                git_config(as_user, as_user_email, as_user_name)

            if 'origin' in sudo('git remote', user=as_user):
                if remote not in sudo('git remote show origin', user=as_user):
                    sudo('git remote rm origin', user=as_user)
                    sudo('git remote add origin %s' % remote, user=as_user)
            else:
                sudo('git remote add origin %s' % remote, user=as_user)

            sudo('git fetch', user=as_user)
            
            if force:
                with api.settings(warn_only=True):
                    sudo('git stash && git stash clear', user=as_user)

            sudo('git checkout %s' % commit_id, user=as_user)
            if update_submodules:
                sudo('git submodule update --init', user=as_user)


def link_ensure(link, target, mode=None, owner=None, group=None):
    """Ensures that there is a remote symbolic link at the given location, pointing to the given target.

    Optionally update the mode/owner/group.
    """
    v = {'link': link, 'target': target}
    if 'OK' not in run("[[ -L '%(link)s' && `readlink '%(link)s'` = '%(target)s' ]] && echo OK ; true" % v):
        run("rm -f %(link)s && ln -s '%(target)s' '%(link)s'" % v)
    if mode or owner or group:
        file_attribs(link, mode=mode, owner=owner, group=group)


def command_check(command):
    """Tests if the given command is available on the system."""
    return run("which '%s' >& /dev/null && echo OK ; true" % command).endswith("OK")


def package_update(package=None):
    """Updates the package database (when no argument) or update the package
    or list of packages given as argument."""
    if package == None:
        sudo("apt-get --yes update")
    else:
        if not isinstance(package, basestring):
            package = " ".join(package)
        sudo("apt-get --yes upgrade " + package)


def package_install(package, update=False):
    """Installs the given package/list of package, optionnaly updating the package
    database."""
    if update: sudo("apt-get --yes update")
    if not isinstance(package, basestring):
        package = " ".join(package)
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


def user_ensure(name, passwd=None, home=None, uid=None, gid=None, shell=None, dirs=(), files=()):
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
    for record in dirs:
        dir_ensure(record['location'], owner=name, group=record.get('group', name), mode=record.get('mode'))
    for record in files:
        file_write(record['location'], record['source'],
                   owner=name,
                   group=record.get('group', name),
                   mode=record.get('mode'))


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


def upstart_ensure(name, restart=False, kwargs=None):
    """Ensures that the given upstart service is running, restarting it if necessary"""
    if upstart_status(name, kwargs).find("/running") >= 0:
        if restart:
            if not isinstance(restart, basestring):
                restart = 'restart'
            upstart_(name, restart, kwargs)
    else:
        upstart_start(name, kwargs)


def upstart_(name, command, kwargs=None):
    if kwargs is None:
        kwargs = {}
    return sudo("%s %s %s" % (command, name, ' '.join('%s=%s' % (k, v)
                                                      for k, v in kwargs.items())))


@api.task
def upstart_start(name, kwargs=None):
    """Start the named upstart service.
    """
    return upstart_(name, 'start', kwargs)


@api.task
def upstart_stop(name, kwargs=None):
    """Stop the named upstart service.
    """
    return upstart_(name, 'stop', kwargs)


@api.task
def upstart_status(name, kwargs=None):
    """Return the status of the named upstart service.
    """
    return upstart_(name, 'status', kwargs)


@api.task
def upstart_restart(name, kwargs=None):
    """Restart the named upstart service.
    """
    return upstart_(name, 'restart', kwargs)


@api.task
def upstart_reload(name, kwargs=None):
    """Reload the named upstart service.
    """
    return upstart_(name, 'reload', kwargs)


@api.task
def upstart_emit(event, kwargs=None):
    """Emit the given upstart event.
    """
    return upstart_(event, 'emit', kwargs)


def service_ensure(name, restart=False):
    """Ensures that the given init.d service is running, restarting it if necessary
    """
    with api.settings(warn_only = True):
        if service_(name, 'status').find('running') >= 0:
            if restart:
                if not isinstance(restart, basestring):
                    restart = 'restart'
                return service_(name, restart)
        else:
            return service_start(name)


@api.task
def service_(name, command):
    """Pass the given command to the named init.d service.
    """
    return sudo("service %s %s" % (name, command), combine_stderr=True)


@api.task
def service_stop(name):
    """Stop the named init.d service.
    """
    return service_(name, 'stop')


@api.task
def service_start(name):
    """Start the named init.d service.
    """
    return service_(name, 'start')


def file_copy(source, target,
              mode_target=None, mode=None, owner=None, group=None):
    sudo('cp %s %s' % (source, target))
    with mode_sudo():
        file_attribs(target if mode_target is None else mode_target,
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
        for line in msg.splitlines():
            logger.info(line)
        with api.hide('running', 'stdout', 'warnings'):
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


def enable_nginx_site(site, source):
    with mode_sudo():
        file_write('/etc/nginx/sites-available/%s' % site, path(source).text(),
                   mode=644, owner='root', group='root')
        if file_exists('/etc/nginx/sites-enabled/%s' % site):
            sudo('rm /etc/nginx/sites-enabled/%s' % site)
        link_ensure('/etc/nginx/sites-enabled/' + site, '/etc/nginx/sites-available/' + site)
    enqueue(100, sudo, '/etc/init.d/nginx reload')


def enable_munin_plugin(plugin, link_name=None):
    if link_name is None:
        link_name = plugin
    with mode_sudo():
        if file_exists('/etc/munin/plugins/%s' % plugin):
            sudo('rm /etc/munin/plugins/%s' % plugin)
        link_ensure('/etc/munin/plugins/' + link_name, '/usr/share/munin/plugins/' + plugin)


def enable_logrotation(name, source):
    with mode_sudo():
        file_write('/etc/logrotate.d/%s' % name, path(source).text(),
                   mode=644, owner='root', group='root')


# DB management
def create_psql_user(db_user, db_user_password):
    with api.settings(warn_only=True):
        with api.hide('running', 'stdout', 'warnings'):
            with api.hide('running', ):
                result = sudo('''psql -c "CREATE USER %s WITH NOCREATEDB NOCREATEUSER ENCRYPTED PASSWORD E'%s'"''' % (
                    db_user, db_user_password), user='postgres')
                if 'already exists' in result:
                    sudo('''psql -c "ALTER ROLE %s ENCRYPTED PASSWORD E'%s'"''' % (
                        db_user, db_user_password), user='postgres')


def create_psql_db(db, owner='postgres'):
    with api.settings(warn_only=True):
        sudo('psql -c "CREATE DATABASE %s WITH OWNER %s"' % (
            db, owner), user='postgres')


# Port knocking
# @api.task
# def knock(host, *ports):
#     """Knock on servers to open up ssh.
#     """
#     for port in ports:
#         #create an INET, STREAMing socket
#         print "Knocking on", host, port
#         try:
#             s = socket.socket(proto=socket.SOL_TCP)
#             s.settimeout(1)
#             s.connect((host, int(port)))
#         except socket.timeout:
#             print "Knock..."
#         time.sleep(1)
    

### Job queue managers
def enqueue(priority, func, *args, **kwargs):
    api.env.job_queue.append((priority, func, args, kwargs))


def run_queued():
    api.env.job_queue.sort()
    for priority, func, args, kwargs in api.env.job_queue:
        func(*args, **dict(kwargs))
    api.env.job_queue[:] = ()


# Role management
def setup_roles(**kwargs):
    if kwargs:
        for role, host in kwargs.iteritems():
            api.env.roledefs[role] = [host]
    api.env.roledefs['all'] = list(set(host for hosts in api.env.roledefs.itervalues() for host in hosts))
    # default to all roles.
    if not api.env.roles:
        api.env.roles = list(api.env.roledefs.keys())

    # Move 'all' to the front of the list.
    api.env.roles.sort(lambda a, b: -1 if a == 'all' else cmp(a, b))


def iterhosts(verb=''):
    for role in api.env.roles:
        logger.info("###########################################")
        logger.info("##### %s Role: %s", verb, role)
        logger.info("###########################################")
        logger.info("###########################################")
        notify('%s Role: %s' % (verb, role), sticky=False)
        api.env.role_string = role
        
        for host in api.env.roledefs[api.env.role_string]:
            notify('%s %s as role %s' % (verb, host, role), sticky=False)

            with api.settings(host_string=host):
                yield role, host


def on_hosts(function):
    def wrapper(*args, **kwargs):
        if api.env.host_string:
            function(*args)
        else:
            setup_roles(**kwargs)
            for role, host in iterhosts(function.__doc__):
                function(*args)
    wrapper.__name__ = function.__name__
    wrapper.__doc__ = function.__doc__
    return wrapper

    
@api.task
def call(name, *args, **kwargs):
    print "Calling", name
    from fabric.tasks import execute
    execute(name, *args, **kwargs)


### Main Deploy task
@api.task
@notifies
def deploy(**kwargs):
    """Deploy the specified roles.
    """
    setup_roles(**kwargs)
    notify('Deploying to %s.'% ', '.join(api.env.roles), sticky=False)

    for start in api.env.on_start:
        start()

    for role, host in iterhosts('Deploying to'):
        with emit_events('all', host, api.env.target, api.env.role_string):
            with tag('system', 'packages'):
                install_system_packages()
            with tag('python', 'packages'):
                install_python_packages()

            logger.info('Running queued tasks.')
        run_queued()

    for role, host in iterhosts('Setting up firewall on'):
        with tag('firewall'):
            apply_firewall()

    for stop in api.env.on_stop:
        stop()

    notify('Deployed to %s.\nDone.' % ', '.join(api.env.roles), sticky=False)


### Deploy helpers
@notifies
def install_system_packages():
    """Install system packages.
    """
    update_by_default = api.env.get('update_system', True)
    if api.env.setdefault('roles_update_system', defaultdict(lambda: update_by_default))[api.env.role_string]:
        package_update()
    packages = api.env.system_packages.get(api.env.role_string, ())

    with emit_events(*packages):
        # In case the before events added dependencies:
        install_packages = api.env.system_packages.get(api.env.role_string, ())

        if install_packages:
            package_install(install_packages)


@notifies
def install_python_packages():
    """Install systemwide python packages.
    """
    update_by_default = api.env.get('upgrade_python', False)
    packages = ' '.join(api.env.python_packages.get(api.env.role_string, ()))
    pip_options = api.env.get('pip_options', [])
    find_links = api.env.get('pip_find_links', None)
    if find_links:
        find_links = ' --find-links=' + find_links + ' '
    if packages:
        if update_by_default:
            packages = ' --upgrade ' + packages
        if find_links:
            packages = find_links + packages
        if pip_options:
            packages = '%s %s' % (' '.join(pip_options), packages)
        sudo('pip install %s' % packages)
    else:
        logger.info('No python packages to install!')


@notifies
def apply_firewall():
    """Apply firewall rules.
    """
    if api.env.firewalls and command_check('ufw'):
        firewalls = api.env.firewalls[api.env.role_string]
        for command in firewalls:
            if command.startswith('$'):
                sudo(command[1:])
            else:
                sudo('ufw %s' % command)

        if firewalls:
            sudo('yes|sudo ufw enable')
            sudo('ufw reload')


@notifies
@api.task
def maintenance_on():
    """Turn on maintenance mode.
    """
    before_events('maintenance')


@notifies
@api.task
@after('maintenance')
def maintenance_off():
    """Turn off maintenance mode.
    """
    after_events('maintenance')


@contextlib.contextmanager
def maintenance():
    """Context manager for entering and exiting maintenance mode for a block of code.
    """
    logger.info('Entering maintenance mode.')
    with emit_events('maintenance'):
        yield
    logger.info('Leaving maintenance mode.')
