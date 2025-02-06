Troubleshooting
===============

Local webserver
---------------

Drop firewall::

  sudo firewall-cmd --add-service=http


DNS / hosts file issues
-----------------------

Flush cache
^^^^^^^^^^^

Note: some resolvers cache NX.

Max OS X::

  dscacheutil -flushcache

Windows::

  ipconfig /flush  -- or is it /flushdns ?


mod_lookup_identity
-------------------

To flush cache::

  $ sudo sss_cache -E
