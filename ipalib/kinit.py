#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
import logging
import os
import re
import time

import gssapi
import ctypes

from ipapython.kerberos import Principal
import ipapython.kerberos as krb5
from ipaplatform.paths import paths
from ipapython.ipautil import run
from ipalib.constants import PATTERN_GROUPUSER_NAME
from ipalib import api, cli, krb_utils
from ipalib.util import validate_hostname

logger = logging.getLogger(__name__)

PATTERN_REALM = '@?([a-zA-Z0-9.-]*)$'
PATTERN_PRINCIPAL = '(' + PATTERN_GROUPUSER_NAME[:-1] + ')' + PATTERN_REALM
PATTERN_SERVICE = '([a-zA-Z0-9.-]+)/([a-zA-Z0-9.-]+)' + PATTERN_REALM

user_pattern = re.compile(PATTERN_PRINCIPAL)
service_pattern = re.compile(PATTERN_SERVICE)


def validate_principal(principal):
    # TODO: use Principal() to verify value?
    if isinstance(principal, Principal):
        principal = str(principal)
    elif not isinstance(principal, str):
        raise RuntimeError('Invalid principal: not a string')
    if ('/' in principal) and (' ' in principal):
        raise RuntimeError('Invalid principal: bad spacing')
    else:
        # For a user match in the regex
        # username = match[1]
        # realm = match[2]
        match = user_pattern.match(principal)
        if match is None:
            match = service_pattern.match(principal)
            if match is None:
                raise RuntimeError('Invalid principal: cannot parse')
            else:
                # service = match[1]
                hostname = match[2]
                # realm = match[3]
                try:
                    validate_hostname(hostname)
                except ValueError as e:
                    raise RuntimeError(str(e))
    return principal


def kinit_keytab(principal, keytab, ccache_name=None, config=None, attempts=1):
    """
    Given a ccache_path, keytab file and a principal kinit as that user.

    The optional parameter 'attempts' specifies how many times the credential
    initialization should be attempted in case of non-responsive KDC.
    """
    validate_principal(principal)
    errors_to_retry = {
        krb_utils.KRB5KDC_ERR_SVC_UNAVAILABLE, krb_utils.KRB5_KDC_UNREACH
    }
    logger.debug("Initializing principal %s using keytab %s",
                 principal, keytab)
    store = {'client_keytab': keytab}
    if ccache_name is not None:
        logger.debug("using ccache %s", ccache_name)
        store['ccache'] = ccache_name
    for attempt in range(1, attempts + 1):
        old_config = os.environ.get('KRB5_CONFIG')
        if config is not None:
            os.environ['KRB5_CONFIG'] = config
        else:
            os.environ.pop('KRB5_CONFIG', None)
        try:
            name = gssapi.Name(
                str(principal), gssapi.NameType.kerberos_principal
            )
            cred = gssapi.Credentials(name=name, store=store, usage='initiate')
            logger.debug("Attempt %d/%d: success", attempt, attempts)
            return cred
        except gssapi.exceptions.GSSError as e:
            if e.min_code not in errors_to_retry:  # pylint: disable=no-member
                raise
            logger.debug("Attempt %d/%d: failed: %s", attempt, attempts, e)
            if attempt == attempts:
                logger.debug("Maximum number of attempts (%d) reached",
                             attempts)
                raise
            logger.debug("Waiting 5 seconds before next retry")
            time.sleep(5)
        finally:
            if old_config is not None:
                os.environ['KRB5_CONFIG'] = old_config
            else:
                os.environ.pop('KRB5_CONFIG', None)

        return None


def _run_env(config=None):
    """Common os.environ for kinit

    Passes KRB5* and GSS* envs like KRB5_TRACE
    """
    env = {"LC_ALL": "C"}
    for key, value in os.environ.items():
        if key.startswith(("KRB5", "GSS")):
            env[key] = value
    if config is not None:
        env["KRB5_CONFIG"] = config
    return env


def kinit_password(principal, password, ccache_name=None, config=None,
                   armor_ccache_name=None, canonicalize=False,
                   enterprise=False, lifetime=None):
    """
    perform interactive kinit as principal using password. If using FAST for
    web-based authentication, use armor_ccache_path to specify http service
    ccache.

    :param principal: principal name
    :param password: user password
    :param ccache_name: location of ccache (default: default location)
    :param config: path to krb5.conf (default: default location)
    :param armor_ccache_name: armor ccache for FAST (-T)
    :param canonicalize: request principal canonicalization (-C)
    :param enterprise: use enterprise principal (-E)
    :param lifetime: request TGT lifetime (-l)
    """
    validate_principal(principal)
    logger.debug("Initializing principal %s using password", principal)
    args = [paths.KINIT]
    if ccache_name is not None:
        args.extend(['-c', ccache_name])
    if armor_ccache_name is not None:
        logger.debug("Using armor ccache %s for FAST webauth",
                     armor_ccache_name)
        args.extend(['-T', armor_ccache_name])

    if lifetime:
        args.extend(['-l', lifetime])

    if canonicalize:
        logger.debug("Requesting principal canonicalization")
        args.append('-C')

    if enterprise:
        logger.debug("Using enterprise principal")
        args.append('-E')

    args.extend(['--', str(principal)])
    env = _run_env(config)

    # this workaround enables us to capture stderr and put it
    # into the raised exception in case of unsuccessful authentication
    result = run(args, stdin=password, env=env, raiseonerr=False,
                 capture_error=True)
    if result.returncode:
        raise RuntimeError(result.error_output)
    return result


def kinit_armor(ccache_name, pkinit_anchors=None):
    """
    perform anonymous pkinit to obtain anonymous ticket to be used as armor
    for FAST.

    :param ccache_name: location of the armor ccache (required)
    :param pkinit_anchor: if not None, the location of PKINIT anchor file to
        use. Otherwise the value from Kerberos client library configuration is
        used

    :raises: CalledProcessError if the anonymous PKINIT fails
    """
    logger.debug("Initializing anonymous ccache")

    env = _run_env()
    args = [paths.KINIT, '-n', '-c', ccache_name]

    if pkinit_anchors is not None:
        for pkinit_anchor in pkinit_anchors:
            args.extend(['-X', 'X509_anchors=FILE:{}'.format(pkinit_anchor)])

    # this workaround enables us to capture stderr and put it
    # into the raised exception in case of unsuccessful authentication
    return run(args, env=env, raiseonerr=True, capture_error=True)


def kinit_pkinit(
        principal,
        user_identity,
        ccache_name=None,
        config=None,
        pkinit_anchors=None,
):
    """Perform kinit with X.509 identity (PKINIT)

    :param principal: principal name
    :param user_identity: X509_user_identity paramemter
    :param ccache_name: location of ccache (default: default location)
    :param config: path to krb5.conf (default: default location)
    :param pkinit_anchor: if not None, the PKINIT anchors to use. Otherwise
        the value from Kerberos client library configuration is used. Entries
        must be prefixed with FILE: or DIR:

    user identity example:
       FILE:filename[,keyfilename]
       PKCS12:filename
       PKCS11:...
       DIR:directoryname

    :raises: CalledProcessError if PKINIT fails
    """
    validate_principal(principal)
    logger.debug(
        "Initializing principal %s using PKINIT %s", principal, user_identity
    )

    args = [paths.KINIT]
    if ccache_name is not None:
        args.extend(['-c', ccache_name])
    if pkinit_anchors is not None:
        for pkinit_anchor in pkinit_anchors:
            assert pkinit_anchor.startswith(("FILE:", "DIR:", "ENV:"))
            args.extend(["-X", f"X509_anchors={pkinit_anchor}"])
    args.extend(["-X", f"X509_user_identity={user_identity}"])
    args.extend(['--', str(principal)])

    # this workaround enables us to capture stderr and put it
    # into the raised exception in case of unsuccessful authentication
    # Unsuccessful pkinit can lead to a password prompt. Send \n to skip
    # prompt.
    env = _run_env(config)
    return run(args, env=env, stdin="\n", raiseonerr=True, capture_error=True)


@krb5.krb5_prompter_fct
def _kinit_default_callback(context, data, name, banner, num_prompts, prompts):
    textui = cli.textui(api)
    if name:
        textui.print_name(name.decode('utf-8'))
    if banner:
        textui.print_summary(banner.decode('utf-8'))

    for i in range(num_prompts):
        prompt = prompts[i].prompt.decode('utf-8')
        if prompts[i].hidden:
            reply = textui.prompt_password(prompt, confirm=False)
        else:
            reply = textui.prompt(prompt)
        if reply:
            # create_string_buffer will have '\0' trailer
            buf = ctypes.create_string_buffer(reply.encode("utf-8"))
            r = prompts[i].reply.contents
            # C string size without '\0' trailer
            r.length = len(buf) - 1
            # Copy the whole string, including the trailer
            ctypes.memmove(r.data, buf, r.length + 1)
    return 0
