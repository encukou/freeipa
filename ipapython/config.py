# Authors: Karl MacMillan <kmacmill@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# pylint: disable=deprecated-module
from optparse import (
    Option, Values, OptionParser, IndentedHelpFormatter, OptionValueError)
# pylint: enable=deprecated-module
from copy import copy

from ipapython.dn import DN


class IPAFormatter(IndentedHelpFormatter):
    """Our own optparse formatter that indents multiple lined usage string."""
    def format_usage(self, usage):
        usage_string = "Usage:"
        spacing = " " * len(usage_string)
        lines = usage.split("\n")
        ret = "%s %s\n" % (usage_string, lines[0])
        for line in lines[1:]:
            ret += "%s %s\n" % (spacing, line)
        return ret

def check_ip_option(option, opt, value):
    from ipapython.ipautil import CheckedIPAddress

    ip_local = option.ip_local is True
    ip_netmask = option.ip_netmask is True
    try:
        return CheckedIPAddress(value, parse_netmask=ip_netmask, match_local=ip_local)
    except Exception as e:
        raise OptionValueError("option %s: invalid IP address %s: %s" % (opt, value, e))

def check_dn_option(option, opt, value):
    try:
        return DN(value)
    except Exception as e:
        raise OptionValueError("option %s: invalid DN: %s" % (opt, e))

class IPAOption(Option):
    """
    optparse.Option subclass with support of options labeled as
    security-sensitive such as passwords.
    """
    ATTRS = Option.ATTRS + ["sensitive", "ip_local", "ip_netmask"]
    TYPES = Option.TYPES + ("ip", "dn")
    TYPE_CHECKER = copy(Option.TYPE_CHECKER)
    TYPE_CHECKER["ip"] = check_ip_option
    TYPE_CHECKER["dn"] = check_dn_option

class IPAOptionParser(OptionParser):
    """
    optparse.OptionParser subclass that uses IPAOption by default
    for storing options.
    """
    def __init__(self,
                 usage=None,
                 option_list=None,
                 option_class=IPAOption,
                 version=None,
                 conflict_handler="error",
                 description=None,
                 formatter=None,
                 add_help_option=True,
                 prog=None):
        OptionParser.__init__(self, usage, option_list, option_class,
                              version, conflict_handler, description,
                              formatter, add_help_option, prog)

    def get_safe_opts(self, opts):
        """
        Returns all options except those with sensitive=True in the same
        fashion as parse_args would
        """
        all_opts_dict = dict([ (o.dest, o) for o in self._get_all_options() if hasattr(o, 'sensitive') ])
        safe_opts_dict = {}

        for option, value in opts.__dict__.items():
            if all_opts_dict[option].sensitive != True:
                safe_opts_dict[option] = value

        return Values(safe_opts_dict)

def verify_args(parser, args, needed_args = None):
    """Verify that we have all positional arguments we need, if not, exit."""
    if needed_args:
        needed_list = needed_args.split(" ")
    else:
        needed_list = []
    len_need = len(needed_list)
    len_have = len(args)
    if len_have > len_need:
        parser.error("too many arguments")
    elif len_have < len_need:
        parser.error("no %s specified" % needed_list[len_have])


def add_standard_options(parser):
    parser.add_option("--realm", dest="realm", help="Override default IPA realm")
    parser.add_option("--server", dest="server",
                      help="Override default FQDN of IPA server")
    parser.add_option("--domain", dest="domain", help="Override default IPA DNS domain")
