# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Functionality for Command Line Interface.
"""

import re
import sys
import code
import optparse
import frontend
import errors
import plugable
import ipa_types


def exit_error(error):
    sys.exit('ipa: ERROR: %s' % error)


def to_cli(name):
    """
    Takes a Python identifier and transforms it into form suitable for the
    Command Line Interface.
    """
    assert isinstance(name, str)
    return name.replace('_', '-')


def from_cli(cli_name):
    """
    Takes a string from the Command Line Interface and transforms it into a
    Python identifier.
    """
    return str(cli_name).replace('-', '_')


class text_ui(frontend.Application):
    """
    Base class for CLI commands with special output needs.
    """

    def print_dashed(self, string, top=True, bottom=True):
        dashes = '-' * len(string)
        if top:
            print dashes
        print string
        if bottom:
            print dashes

    def print_name(self, **kw):
        self.print_dashed('%s:' % self.name, **kw)


class help(frontend.Application):
    'Display help on a command.'

    takes_args = ['command']

    def run(self, key):
        key = str(key)
        if key not in self.application:
            print 'help: no such command %r' % key
            sys.exit(2)
        cmd = self.application[key]
        print 'Purpose: %s' % cmd.doc
        self.application.build_parser(cmd).print_help()


class console(frontend.Application):
    'Start the IPA interactive Python console.'

    def run(self):
        code.interact(
            '(Custom IPA interactive Python console)',
            local=dict(api=self.api)
        )



class show_api(text_ui):
    'Show attributes on dynamic API object'

    takes_args = ('namespaces*',)

    def run(self, namespaces):
        if namespaces is None:
            names = tuple(self.api)
        else:
            for name in namespaces:
                if name not in self.api:
                    exit_error('api has no such namespace: %s' % name)
            names = namespaces
        lines = self.__traverse(names)
        ml = max(len(l[1]) for l in lines)
        self.print_name()
        first = True
        for line in lines:
            if line[0] == 0 and not first:
                print ''
            if first:
                first = False
            print '%s%s %r' % (
                ' ' * line[0],
                line[1].ljust(ml),
                line[2],
            )
        if len(lines) == 1:
            s = '1 attribute shown.'
        else:
            s = '%d attributes show.' % len(lines)
        self.print_dashed(s)


    def __traverse(self, names):
        lines = []
        for name in names:
            namespace = self.api[name]
            self.__traverse_namespace('%s' % name, namespace, lines)
        return lines

    def __traverse_namespace(self, name, namespace, lines, tab=0):
        lines.append((tab, name, namespace))
        for member_name in namespace:
            member = namespace[member_name]
            lines.append((tab + 1, member_name, member))
            if not hasattr(member, '__iter__'):
                continue
            for n in member:
                attr = member[n]
                if isinstance(attr, plugable.NameSpace) and len(attr) > 0:
                    self.__traverse_namespace(n, attr, lines, tab + 2)


class plugins(text_ui):
    """Show all loaded plugins"""

    def run(self):
        self.print_name()
        first = True
        for p in sorted(self.api.plugins, key=lambda o: o.plugin):
            if first:
                first = False
            else:
                print ''
            print '  plugin: %s' % p.plugin
            print '  in namespaces: %s' % ', '.join(p.bases)
        if len(self.api.plugins) == 1:
            s = '1 plugin loaded.'
        else:
            s = '%d plugins loaded.' % len(self.api.plugins)
        self.print_dashed(s)





cli_application_commands = (
    help,
    console,
    show_api,
    plugins,

)


class KWCollector(object):
    def __init__(self):
        object.__setattr__(self, '_KWCollector__d', {})

    def __setattr__(self, name, value):
        if name in self.__d:
            v = self.__d[name]
            if type(v) is tuple:
                value = v + (value,)
            else:
                value = (v, value)
        self.__d[name] = value
        object.__setattr__(self, name, value)

    def __todict__(self):
        return dict(self.__d)


class CLI(object):
    __d = None
    __mcl = None

    def __init__(self, api):
        self.__api = api

    def __get_api(self):
        return self.__api
    api = property(__get_api)

    def print_commands(self):
        std = set(self.api.Command) - set(self.api.Application)
        print '\nStandard IPA commands:'
        for key in sorted(std):
            cmd = self.api.Command[key]
            self.print_cmd(cmd)
        print '\nSpecial CLI commands:'
        for cmd in self.api.Application():
            self.print_cmd(cmd)
        print ''

    def print_cmd(self, cmd):
        print '  %s  %s' % (
            to_cli(cmd.name).ljust(self.mcl),
            cmd.doc,
        )

    def __contains__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return key in self.__d

    def __getitem__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return self.__d[key]

    def finalize(self):
        api = self.api
        for klass in cli_application_commands:
            api.register(klass)
        api.finalize()
        for a in api.Application():
            a.set_application(self)
        self.build_map()

    def build_map(self):
        assert self.__d is None
        self.__d = dict(
            (c.name.replace('_', '-'), c) for c in self.api.Command()
        )

    def run(self):
        self.finalize()
        if len(sys.argv) < 2:
            self.print_commands()
            print 'Usage: ipa COMMAND'
            sys.exit(2)
        key = sys.argv[1]
        if key not in self:
            self.print_commands()
            print 'ipa: ERROR: unknown command %r' % key
            sys.exit(2)
        self.run_cmd(
            self[key],
            list(s.decode('utf-8') for s in sys.argv[2:])
        )

    def run_cmd(self, cmd, argv):
        kw = self.parse(cmd, argv)
        self.run_interactive(cmd, kw)

    def run_interactive(self, cmd, kw):
        for param in cmd.params():
            if param.name not in kw:
                if not param.required:
                    continue
                default = param.get_default(**kw)
                if default is None:
                    prompt = '%s: ' % param.name
                else:
                    prompt = '%s [%s]: ' % (param.name, default)
                error = None
                while True:
                    if error is not None:
                        print '>>> %s: %s' % (param.name, error)
                    raw = raw_input(prompt)
                    try:
                        value = param(raw, **kw)
                        if value is not None:
                            kw[param.name] = value
                        break
                    except errors.ValidationError, e:
                        error = e.error
        cmd(**kw)

    def parse(self, cmd, argv):
        parser = self.build_parser(cmd)
        (kwc, args) = parser.parse_args(argv, KWCollector())
        kw = kwc.__todict__()
        try:
            arg_kw = cmd.args_to_kw(*args)
        except errors.ArgumentError, e:
            exit_error('%s %s' % (to_cli(cmd.name), e.error))
        assert set(arg_kw).intersection(kw) == set()
        kw.update(arg_kw)
        return kw

    def build_parser(self, cmd):
        parser = optparse.OptionParser(
            usage=self.get_usage(cmd),
        )
        for option in cmd.options():
            parser.add_option('--%s' % to_cli(option.name),
                metavar=option.type.name.upper(),
                help=option.doc,
            )
        return parser

    def get_usage(self, cmd):
        return ' '.join(self.get_usage_iter(cmd))

    def get_usage_iter(self, cmd):
        yield 'Usage: %%prog %s' % to_cli(cmd.name)
        for arg in cmd.args():
            name = to_cli(arg.name).upper()
            if arg.multivalue:
                name = '%s...' % name
            if arg.required:
                yield name
            else:
                yield '[%s]' % name

    def __get_mcl(self):
        """
        Returns the Max Command Length.
        """
        if self.__mcl is None:
            if self.__d is None:
                return None
            self.__mcl = max(len(k) for k in self.__d)
        return self.__mcl
    mcl = property(__get_mcl)
