# Authors:
#   Rob Crittenden <rcritten@@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

"""
Backend plugin for RA activities.

The `ra` plugin provides access to the CA to issue, retrieve, and revoke
certificates via the following methods:

    * `ra.check_request_status()` - check certificate request status.
    * `ra.get_certificate()` - retrieve an existing certificate.
    * `ra.request_certificate()` - request a new certificate.
    * `ra.revoke_certificate()` - revoke a certificate.
    * `ra.take_certificate_off_hold()` - take a certificate off hold.
"""

from __future__ import absolute_import

from ipalib import Backend
from ipalib import errors
import os
from ipaplatform.paths import paths


class rabase(Backend):
    """
    Request Authority backend plugin.
    """
    def __init__(self, api):
        self.ca_cert = api.env.tls_ca_cert
        if api.env.in_tree:
            self.client_certfile = os.path.join(
                api.env.dot_ipa, 'ra-agent.pem')
            self.client_keyfile = os.path.join(api.env.dot_ipa, 'ra-agent.key')
        else:
            self.client_certfile = paths.RA_AGENT_PEM
            self.client_keyfile = paths.RA_AGENT_KEY
        super(rabase, self).__init__(api)

    def check_request_status(self, request_id):
        """
        Check status of a certificate signing request.

        :param request_id: request ID
        """
        raise errors.NotImplementedError(name='%s.check_request_status' % self.name)

    def get_certificate(self, serial_number):
        """
        Retrieve an existing certificate.

        :param serial_number: certificate serial number
        """
        raise errors.NotImplementedError(name='%s.get_certificate' % self.name)

    def request_certificate(
            self, csr, profile_id, ca_id, request_type='pkcs10'):
        """
        Submit certificate signing request.

        :param csr: The certificate signing request.
        :param profile_id: Profile to use for this request.
        :param ca_id: The Authority ID to send request to. ``None`` is allowed.
        :param request_type: The request type (defaults to ``'pkcs10'``).
        """
        raise errors.NotImplementedError(name='%s.request_certificate' % self.name)

    def revoke_certificate(self, serial_number, revocation_reason=0):
        """
        Revoke a certificate.

        The integer ``revocation_reason`` code must have one of these values:

            * ``0`` - unspecified
            * ``1`` - keyCompromise
            * ``2`` - cACompromise
            * ``3`` - affiliationChanged
            * ``4`` - superseded
            * ``5`` - cessationOfOperation
            * ``6`` - certificateHold
            * ``8`` - removeFromCRL
            * ``9`` - privilegeWithdrawn
            * ``10`` - aACompromise

        Note that reason code ``7`` is not used.  See RFC 5280 for more details:

            http://www.ietf.org/rfc/rfc5280.txt

        :param serial_number: Certificate serial number.
        :param revocation_reason: Integer code of revocation reason.
        """
        raise errors.NotImplementedError(name='%s.revoke_certificate' % self.name)

    def take_certificate_off_hold(self, serial_number):
        """
        Take revoked certificate off hold.

        :param serial_number: Certificate serial number.
        """
        raise errors.NotImplementedError(name='%s.take_certificate_off_hold' % self.name)


    def find(self, options):
        """
        Search for certificates

        :param options: dictionary of search options
        """
        raise errors.NotImplementedError(name='%s.find' % self.name)

    def updateCRL(self, wait='false'):
        """
        Force update of the CRL

        :param wait: if true, the call will be synchronous and return only
                     when the CRL has been generated
        """
        raise errors.NotImplementedError(name='%s.updateCRL' % self.name)

    def approve_request(self, request_id):
        """
        Approve a certificate signing request.

        :param request_id: request ID
        """
        raise errors.NotImplementedError(name='%s.approve_request' % self.name)

    def list_profiles(self, size):
        """
        Return the list of available profiles from the CA.

        :param size: the maximum number of profiles to return
        """
        raise errors.NotImplementedError(name='%s.list_profiles' % self.name)
