#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import ipapython.kerberos as krb5
import ctypes

CONF_REALM = b"X-CACHECONF:"
CONF_NAME = b"krb5_ccache_conf_data"


def store_data(princ_name, key, value):
    """
    Stores the session cookie in a hidden ccache entry.
    """
    if not isinstance(princ_name, bytes):
        princ_name = princ_name.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('ascii')
    if not isinstance(value, bytes):
        value = value.encode('utf-8')

    # FILE ccaches grow every time an entry is stored, so we need
    # to avoid storing the same entry multiple times.
    oldvalue = get_data(princ_name, key)
    if oldvalue == value:
        return

    context = krb5.krb5_context()
    principal = krb5.krb5_principal()
    ccache = krb5.krb5_ccache()

    try:
        krb5.krb5_init_context(ctypes.byref(context))

        krb5.krb5_parse_name(context, ctypes.c_char_p(princ_name),
                             ctypes.byref(principal))

        krb5.krb5_cc_default(context, ctypes.byref(ccache))

        buf = ctypes.create_string_buffer(value)
        data = krb5._krb5_data()
        data.data = buf.value
        data.length = len(buf)
        krb5.krb5_cc_set_config(context, ccache, principal, key,
                                ctypes.byref(data))

    finally:
        if principal:
            krb5.krb5_free_principal(context, principal)
        if ccache:
            krb5.krb5_cc_close(context, ccache)
        if context:
            krb5.krb5_free_context(context)


def get_data(princ_name, key):
    """
    Gets the session cookie in a hidden ccache entry.
    """
    if not isinstance(princ_name, bytes):
        princ_name = princ_name.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('utf-8')

    context = krb5.krb5_context()
    principal = krb5.krb5_principal()
    srv_princ = krb5.krb5_principal()
    ccache = krb5.krb5_ccache()
    pname_princ = krb5.krb5_principal()
    pname = ctypes.c_char_p()

    try:
        krb5.krb5_init_context(ctypes.byref(context))

        krb5.krb5_cc_default(context, ctypes.byref(ccache))
        krb5.krb5_cc_get_principal(context, ccache, ctypes.byref(principal))

        # We need to parse and then unparse the name in case the pric_name
        # passed in comes w/o a realm attached
        krb5.krb5_parse_name(context, ctypes.c_char_p(princ_name),
                             ctypes.byref(pname_princ))
        krb5.krb5_unparse_name(context, pname_princ, ctypes.byref(pname))

        krb5.krb5_build_principal(context, ctypes.byref(srv_princ),
                                  len(CONF_REALM), ctypes.c_char_p(CONF_REALM),
                                  ctypes.c_char_p(CONF_NAME),
                                  ctypes.c_char_p(key),
                                  pname, ctypes.c_char_p(None))

        # Unfortunately we can't just use krb5_cc_get_config()
        # because of bugs in some ccache handling code in krb5
        # libraries that would always return the first entry
        # stored and not the last one, which is the one we want.
        cursor = krb5.krb5_cc_cursor()
        creds = krb5.krb5_creds()
        got_creds = False
        krb5.krb5_cc_start_seq_get(context, ccache, ctypes.byref(cursor))
        try:
            while True:
                checkcreds = krb5.krb5_creds()
                # the next function will throw an error and break out of the
                # while loop when we try to access past the last cred
                try:
                    krb5.krb5_cc_next_cred(context, ccache,
                                           ctypes.byref(cursor),
                                           ctypes.byref(checkcreds))
                except krb5.KRB5Error:
                    break

                if (krb5.krb5_principal_compare(context, principal,
                                                checkcreds.client) == 1
                    and krb5.krb5_principal_compare(context, srv_princ,
                                                    checkcreds.server) == 1):
                    if got_creds:
                        krb5.krb5_free_cred_contents(context,
                                                     ctypes.byref(creds))
                    creds = checkcreds
                    got_creds = True
                    # We do not stop here, as we want the LAST entry
                    # in the ccache for those ccaches that cannot delete
                    # but only always append, like FILE
                else:
                    krb5.krb5_free_cred_contents(context,
                                                 ctypes.byref(checkcreds))
        finally:
            krb5.krb5_cc_end_seq_get(context, ccache, ctypes.byref(cursor))

        if got_creds:
            data = creds.ticket.data
            krb5.krb5_free_cred_contents(context, ctypes.byref(creds))
            return data

    finally:
        if principal:
            krb5.krb5_free_principal(context, principal)
        if srv_princ:
            krb5.krb5_free_principal(context, srv_princ)
        if pname_princ:
            krb5.krb5_free_principal(context, pname_princ)
        if pname:
            krb5.krb5_free_unparsed_name(context, pname)
        if ccache:
            krb5.krb5_cc_close(context, ccache)
        if context:
            krb5.krb5_free_context(context)
    return None


def remove_data(princ_name, key):
    """
    Removes the hidden ccache entry with the session cookie.
    """
    if not isinstance(princ_name, bytes):
        princ_name = princ_name.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('utf-8')

    context = krb5.krb5_context()
    principal = krb5.krb5_principal()
    ccache = krb5.krb5_ccache()

    try:
        krb5.krb5_init_context(ctypes.byref(context))

        krb5.krb5_parse_name(context, ctypes.c_char_p(princ_name),
                             ctypes.byref(principal))

        krb5.krb5_cc_default(context, ctypes.byref(ccache))

        try:
            krb5.krb5_cc_set_config(context, ccache, principal, key, None)
        except krb5.KRB5Error as e:
            if e.args[0] == krb5.KRB5_CC_NOSUPP:
                # removal not supported with this CC type, just pass
                pass

    finally:
        if principal:
            krb5.krb5_free_principal(context, principal)
        if ccache:
            krb5.krb5_cc_close(context, ccache)
        if context:
            krb5.krb5_free_context(context)
