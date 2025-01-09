# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009,2013  Red Hat
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
Test the `ipaserver/plugins/cert.py` module against a RA.
"""
from __future__ import print_function, absolute_import

import base64
import os

import pytest
import six
from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipapython.certdb import NSSDatabase
from ipapython.dn import DN
from ipapython import dogtag
from ipapython.ipautil import run
from ipatests.test_xmlrpc.testcert import subject_base
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test

if six.PY3:
    unicode = str

# So we can save the cert from issuance and compare it later
cert = None
newcert = None
sn = None

_DOMAIN = api.env.domain
_EXP_CRL_URI = ''.join(['http://ipa-ca.', _DOMAIN, '/ipa/crl/MasterCRL.bin'])
_EXP_OCSP_URI = ''.join(['http://ipa-ca.', _DOMAIN, '/ca/ocsp'])

def is_db_configured():
    """
    Raise an exception if we are testing against lite-server and the
    developer cert database is configured.
    """
    aliasdir = api.env.dot_ipa + os.sep + 'alias' + os.sep + '.pwd'

    if (api.env.xmlrpc_uri == u'http://localhost:8888/ipa/xml' and
       not os.path.isfile(aliasdir)):
        pytest.skip('developer CA not configured in %s' % aliasdir)

# Test setup
#
# This test needs a configured CA behind it in order to work properly
#
# To test against Apache directly then no changes are required. Just be
# sure the xmlrpc_uri in ~/.ipa/default.conf points to Apache.
#
# To test against Dogtag CA in the lite-server:
#
# - Copy the 3 NSS db files from /var/lib/ipa/radb to ~/.ipa/alias
# - Copy /var/lib/ipa/radb/pwdfile.txt to  ~/.ipa/alias/.pwd.
# - Change ownership of these files to be readable by you.
#
# The API tested depends on the value of ~/.ipa/default/ra_plugin when
# running as the lite-server.

class BaseCert(XMLRPC_test):
    host_fqdn = u'ipatestcert.%s' % api.env.domain
    service_princ = u'test/%s@%s' % (host_fqdn, api.env.realm)
    certfile = None
    nssdb = None
    reqfile = None
    subject = None

    @pytest.fixture(autouse=True, scope="class")
    def basecert_setup(self, request, xmlrpc_setup):
        if 'cert_request' not in api.Command:
            pytest.skip('cert_request not registered')
        if 'cert_show' not in api.Command:
            pytest.skip('cert_show not registered')

        is_db_configured()

    @pytest.fixture(autouse=True)
    def basecert_fsetup(self, request):
        self.nssdb = NSSDatabase()
        secdir = self.nssdb.secdir
        self.reqfile = os.path.join(secdir, "test.csr")
        self.certfile = os.path.join(secdir, "cert.crt")
        # Create our temporary NSS database
        self.nssdb.create_db()
        self.subject = DN(('CN', self.host_fqdn), subject_base())

        def fin():
            self.nssdb.close()
        request.addfinalizer(fin)

    def generateCSR(self, subject):
        self.nssdb.run_certutil([
            "-R", "-s", subject,
            "-o", self.reqfile,
            "-z", paths.GROUP,
            "-a",
        ])
        with open(self.reqfile, "rb") as f:
            return f.read().decode('ascii')


@pytest.mark.tier1
class test_cert(BaseCert):
    """
    Test the `cert` plugin.
    """

    def test_0001_cert_add(self):
        """
        Test the `xmlrpc.cert_request` method without --add.

        This should fail because the service principal doesn't exist
        """
        # First create the host that will use this policy
        assert 'result' in api.Command['host_add'](self.host_fqdn, force=True)

        csr = self.generateCSR(str(self.subject))
        with pytest.raises(errors.NotFound):
            api.Command['cert_request'](csr, principal=self.service_princ)

    def test_0002_cert_add(self):
        """
        Test the `xmlrpc.cert_request` method with --add.
        """
        # Our host should exist from previous test
        global cert, sn

        csr = self.generateCSR(str(self.subject))
        res = api.Command['cert_request'](csr, principal=self.service_princ, add=True)['result']
        assert DN(res['subject']) == self.subject
        assert 'cacn' in res
        # save the cert for the service_show/find tests
        cert = res['certificate'].encode('ascii')
        # save cert's SN for URI test
        sn = res['serial_number']

    def test_0003_service_show(self):
        """
        Verify that service-show has the right certificate using service-show.
        """
        res = api.Command['service_show'](self.service_princ)['result']
        assert base64.b64encode(res['usercertificate'][0]) == cert

    def test_0004_service_find(self):
        """
        Verify that service-find has the right certificate using service-find.
        """
        # Assume there is only one service
        res = api.Command['service_find'](self.service_princ)['result']
        assert base64.b64encode(res[0]['usercertificate'][0]) == cert

    def test_0005_cert_uris(self):
        """Test URI details and OCSP-URI in certificate.

        See https://fedorahosted.org/freeipa/ticket/5881
        """
        result = api.Command.cert_show(sn, out=unicode(self.certfile))
        with open(self.certfile, "rb") as f:
            pem_cert = f.read().decode('ascii')
        result = run([paths.OPENSSL, 'x509', '-text'],
                     stdin=pem_cert, capture_output=True)
        assert _EXP_CRL_URI in result.output
        assert _EXP_OCSP_URI in result.output

    def test_0006_cert_renew(self):
        """
        Issue a new certificate for a service
        """
        global newcert

        csr = self.generateCSR(str(self.subject))
        res = api.Command['cert_request'](csr, principal=self.service_princ)['result']
        assert DN(res['subject']) == self.subject
        # save the cert for the service_show/find tests
        newcert = res['certificate'].encode('ascii')

    def test_0007_service_show(self):
        """
        Verify the new certificate with service-show.
        """
        res = api.Command['service_show'](self.service_princ)['result']

        # Both the old and the new certs should be listed as certificates now
        certs_encoded = (
            base64.b64encode(usercert) for usercert in res['usercertificate']
        )
        assert set(certs_encoded) == set([cert, newcert])

    def test_0008_cert_show(self):
        """
        Verify that cert-show shows CA of the certificate without --all
        """
        res = api.Command['cert_show'](sn)['result']
        assert 'cacn' in res
        assert 'valid_not_before' in res
        assert 'valid_not_after' in res

    def test_0009_cert_find(self):
        """
        Verify that cert-find shows CA of the certificate without --all
        """
        res = api.Command['cert_find'](min_serial_number=sn,
                                       max_serial_number=sn)['result'][0]
        assert 'cacn' in res
        assert 'valid_not_before' in res
        assert 'valid_not_after' in res

    def test_00010_san_in_cert(self):
        """
        Test if SAN extension is automatically added with default profile.
        """
        csr = self.generateCSR(str(self.subject))
        res = api.Command[
            'cert_request'](csr, principal=self.service_princ)['result']
        assert 'san_dnsname' in res

    def test_00011_emails_are_valid(self):
        """
        Verify the different scenarios when checking if any email addr
        from DN or SAN extension does not appear in ldap entry.
        """

        from ipaserver.plugins.cert import _emails_are_valid
        email_addrs = [u'any@EmAiL.CoM']
        result = _emails_are_valid(email_addrs, [u'any@email.com'])
        assert result

        email_addrs = [u'any@EmAiL.CoM']
        result = _emails_are_valid(email_addrs, [u'any@email.com',
                                                 u'another@email.com'])
        assert result

        result = _emails_are_valid([], [u'any@email.com'])
        assert result

        email_addrs = [u'invalidEmailAddress']
        result = _emails_are_valid(email_addrs, [])
        assert not result

    def test_00012_cert_find_all(self):
        """
        Test that cert-find --all returns successfully.

        We don't know how many we'll get but there should be at least 10
        by default.
        """
        res = api.Command['cert_find'](all=True)
        assert 'count' in res and res['count'] >= 10

    def test_00013_cert_approve(self):
        """
        Negative test that approving a non-existent request fails gracefully.
        """
        with pytest.raises(errors.NotFound):
            api.Command['cert_approve']('1')

    def test_00014_cert_approve(self):
        """
        Negative test that cert requests for CA profiles fails because the
        request is coming as admin and not as an IPA server host
        principal.
        """
        csr = self.generateCSR(str(self.subject))
        for profile in (
            dogtag.OCSP_PROFILE,
            dogtag.SUBSYSTEM_PROFILE,
            dogtag.AUDIT_PROFILE,
            dogtag.CACERT_PROFILE,
            dogtag.CASERVER_PROFILE,
            dogtag.KRA_AUDIT_PROFILE,
            dogtag.KRA_STORAGE_PROFILE,
            dogtag.KRA_TRANSPORT_PROFILE
        ):
            with pytest.raises(errors.NotFound):
                api.Command['cert_request'](
                    csr,
                    profile_id=profile,
                    principal=self.service_princ,
                    add=True
                )

    def test_99999_cleanup(self):
        """
        Clean up cert test data
        """
        # Now clean things up
        api.Command['host_del'](self.host_fqdn)

        # Verify that the service is gone
        res = api.Command['service_find'](self.service_princ)
        assert res['count'] == 0


@pytest.mark.tier1
class test_cert_find(XMLRPC_test):
    """
    Test the `cert-find` command.
    """
    @pytest.fixture(autouse=True, scope="class")
    def certfind_setup(self, request, xmlrpc_setup):
        if 'cert_find' not in api.Command:
            pytest.skip('cert_find not registered')

        if api.env.ra_plugin != 'dogtag':
            pytest.skip('cert_find for dogtag CA only')

        is_db_configured()

    short = api.env.host.split('.', maxsplit=1)[0]

    def test_0001_find_all_certs(self):
        """
        Search for all certificates.

        We don't know how many we'll get but there should be at least 10
        by default.
        """
        res = api.Command['cert_find']()
        assert 'count' in res and res['count'] >= 10

    def test_0002_find_CA(self):
        """
        Search for the CA certificate.
        """
        res = api.Command['cert_find'](subject=u'Certificate Authority')
        assert 'count' in res and res['count'] == 1

    def test_0003_find_OCSP(self):
        """
        Search for the OCSP certificate.
        """
        res = api.Command['cert_find'](subject=u'OCSP Subsystem')
        assert 'count' in res
        assert res['count'], "No OSCP certificate found"

    def test_0004_find_this_host(self):
        """
        Find all certificates for this IPA server
        """
        res = api.Command['cert_find'](subject=api.env.host)
        assert 'count' in res and res['count'] > 1

    def test_0005_find_this_host_exact(self):
        """
        Find all certificates for this IPA server (exact)
        """
        res = api.Command['cert_find'](subject=api.env.host, exactly=True)
        assert 'count' in res and res['count'] > 1

    def test_0006_find_this_short_host_exact(self):
        """
        Find all certificates for this IPA server short name (exact)
        """
        res = api.Command['cert_find'](subject=self.short, exactly=True)
        assert 'count' in res and res['count'] == 0

    # tests 0007 to 0016 removed

    def test_0017_find_by_issuedon(self):
        """
        Find all certificates issued since 2008
        """
        res = api.Command['cert_find'](issuedon_from=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0018_find_through_issuedon(self):
        """
        Find all certificates issued through 2008
        """
        res = api.Command['cert_find'](issuedon_to=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0019_find_notvalid_before(self):
        """
        Find all certificates valid not before 2008
        """
        res = api.Command['cert_find'](validnotbefore_from=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0020_find_notvalid_before(self):
        """
        Find all certificates valid not before to 2100
        """
        res = api.Command['cert_find'](validnotbefore_to=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0021_find_notvalid_before(self):
        """
        Find all certificates valid not before 2100
        """
        res = api.Command['cert_find'](validnotbefore_from=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0022_find_notvalid_before(self):
        """
        Find all certificates valid not before to 2008
        """
        res = api.Command['cert_find'](validnotbefore_to=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0023_find_notvalid_after(self):
        """
        Find all certificates valid not after 2008
        """
        res = api.Command['cert_find'](validnotafter_from=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0024_find_notvalid_after(self):
        """
        Find all certificates valid not after to 2100
        """
        res = api.Command['cert_find'](validnotafter_to=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0025_find_notvalid_after(self):
        """
        Find all certificates valid not after 2100
        """
        res = api.Command['cert_find'](validnotafter_from=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0026_find_notvalid_after(self):
        """
        Find all certificates valid not after to 2008
        """
        res = api.Command['cert_find'](validnotafter_to=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0027_sizelimit_zero(self):
        """
        Search with a sizelimit of 0
        """
        count_all = api.Command['cert_find']()['count']
        res = api.Command['cert_find'](sizelimit=0)
        assert 'count' in res and res['count'] == count_all

    def test_0028_find_negative_size(self):
        """
        Search with a negative sizelimit
        """
        with pytest.raises(errors.ValidationError):
            api.Command['cert_find'](sizelimit=-100)

    def test_0029_search_for_notfound(self):
        """
        Search for a host that isn't there.
        """
        res = api.Command['cert_find'](subject=u'notfound')
        assert 'count' in res and res['count'] == 0

    def test_0030_search_for_testcerts(self):
        """
        Search for certs created in other tests
        """
        res = api.Command['cert_find'](subject=u'ipatestcert.%s' % api.env.domain)
        assert 'count' in res and res['count'] >= 1

    def test_0031_search_on_invalid_date(self):
        """
        Search using invalid date format
        """
        with pytest.raises(errors.ConversionError):
            api.Command['cert_find'](issuedon_from=u'xyz')


@pytest.mark.tier1
class test_cert_revocation(BaseCert):

    # create CSR, request cert, revoke cert, check cert attributes
    def revoke_cert(self, reason):
        # add host
        assert 'result' in api.Command['host_add'](self.host_fqdn, force=True)

        # generate CSR, request certificate, obtain serial number
        self.csr = self.generateCSR(str(self.subject))
        res = api.Command['cert_request'](self.csr,
                                          principal=self.service_princ,
                                          add=True, all=True)['result']
        serial_number = res['serial_number']

        # REMOVE_FROM_CRL (8) needs to be on hold to revoke per RFC 5280
        if reason == 8:
            assert 'result' in api.Command['cert_revoke'](
                serial_number, revocation_reason=6)

        # revoke created certificate
        assert 'result' in api.Command['cert_revoke'](
            serial_number, revocation_reason=reason)

        # verify that certificate is revoked with correct reason
        res2 = api.Command['cert_show'](serial_number, all=True)['result']

        if reason == 8:
            assert res2['revoked'] is False
        else:
            assert res2['revoked']
            assert res2['revocation_reason'] == reason

        # remove host
        assert 'result' in api.Command['host_del'](self.host_fqdn)

    def test_revoke_with_reason_0(self):
        self.revoke_cert(0)

    def test_revoke_with_reason_1(self):
        self.revoke_cert(1)

    def test_revoke_with_reason_2(self):
        self.revoke_cert(2)

    def test_revoke_with_reason_3(self):
        self.revoke_cert(3)

    def test_revoke_with_reason_4(self):
        self.revoke_cert(4)

    def test_revoke_with_reason_5(self):
        self.revoke_cert(5)

    def test_revoke_with_reason_6(self):
        self.revoke_cert(6)

    def test_revoke_with_reason_8(self):
        self.revoke_cert(8)

    def test_revoke_with_reason_9(self):
        self.revoke_cert(9)

    def test_revoke_with_reason_10(self):
        self.revoke_cert(10)


@pytest.mark.tier1
class test_cert_remove_hold(BaseCert):

    # create CSR, request cert, revoke cert, remove hold
    def test_revoke_and_remove_hold(self):
        # add host
        assert 'result' in api.Command['host_add'](self.host_fqdn, force=True)

        # generate CSR, request certificate, obtain serial number
        self.csr = self.generateCSR(str(self.subject))
        res = api.Command['cert_request'](self.csr,
                                          principal=self.service_princ,
                                          add=True, all=True)['result']
        serial_number = res['serial_number']

        # revoke created certificate
        assert 'result' in api.Command['cert_revoke'](
            serial_number, revocation_reason=6)

        # verify that certificate is revoked with correct reason
        res2 = api.Command['cert_show'](serial_number, all=True)['result']
        assert res2['revoked']
        assert res2['revocation_reason'] == 6

        # remove hold
        res3 = api.Command['cert_remove_hold'](serial_number)['result']
        assert res3['unrevoked']

        # remove host
        assert 'result' in api.Command['host_del'](self.host_fqdn)

    def test_remove_hold_nonexistent_cert(self):
        # remove hold must print 'Certificate ID xx not found'
        with pytest.raises(errors.NotFound,
                           match=r'Certificate ID 0x.* not found'):
            api.Command['cert_remove_hold'](9999)
