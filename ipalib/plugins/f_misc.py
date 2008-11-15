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
Misc frontend plugins.
"""

from ipalib import api, LocalOrRemote


# FIXME: We should not let env return anything in_server
# when mode == 'production'.  This would allow an attacker to see the
# configuration of the server, potentially revealing compromising
# information.  However, it's damn handy for testing/debugging.
class env(LocalOrRemote):
    """Show environment variables"""

    takes_args = ('variables*',)

    def __find_keys(self, variables):
        for key in variables:
            if key in self.env:
                yield (key, self.env[key])

    def execute(self, variables, **options):
        if variables is None:
            return tuple(
                (key, self.env[key]) for key in self.env
            )
        return tuple(self.__find_keys(variables))

    def output_for_cli(self, textui, result, variables, **options):
        if len(result) == 0:
            return
        if len(result) == 1:
            textui.print_keyval(result)
            return
        textui.print_name(self.name)
        textui.print_keyval(result)
        textui.print_count(result, '%d variable', '%d variables')

api.register(env)
