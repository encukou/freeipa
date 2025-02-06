# Authors:
#   Sam Cordry <samcordry@gmail.com>

"""
PGP utilities
"""

import re

import six

if six.PY3:
    unicode = str

__all__ = ["PGPPublicKey"]


class PGPPublicKey:
    """
    OpenPGP public key object.
    """

    __slots__ = ("_key", "_comment", "_options")

    def __init__(self, key, comment=None, options=None):
        if isinstance(key, PGPPublicKey):
            self._key = key._key
            self._comment = key._comment
            self._options = key._options
            return

        if not isinstance(key, (unicode, bytes)):
            raise TypeError(
                "argument must be unicode or bytes, got %s" % type(key).__name__
            )

        valid = self._validate_key(key)

        if not valid:
            raise ValueError("not a valid PGP public key")

        if comment is not None:
            self._comment = comment
        if options is not None:
            self._options = options

    def _validate_key(self, key):
        return re.fullmatch(
            # "^-----BEGIN PGP PUBLIC KEY BLOCK-----\s?([\w\+\/=\s]*)\s?-----END PGP PUBLIC KEY BLOCK-----$",
            r"^[\w\+\/=\s]*$",
            key,
        )

    def key(self):
        return self._key
