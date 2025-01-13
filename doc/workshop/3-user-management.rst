.. _3-user-management:

Unit 3: User management and Kerberos authentication
=====================================================

This unit introduces the ``ipa`` CLI program and the web interface.
We will perform some simple administrative tasks: adding groups and
users and managing group membership.


Web UI
-------

Before being able to access the WebUI, you need to add a profile to your
Firefox configuration. From the workshop folder run ``firefox-profile.sh``
to add the configuration to your user. If you want to remove this
configuration later, use ``firefox-profile.sh clean``.

To visit any workshop related url use ``start-firefox.sh <URL>``. This will
allow the URL in the containers to be accessed from the host.

Visit ``https://server.ipademo.local/``.  You'll get a TLS
*untrusted issuer* warning which you can dismiss (by adding a temporary
exception).  Log in as ``admin``.

Welcome to the FreeIPA Web UI.  Most management activities can be
performed here, or via the ``ipa`` CLI program.  Use the Web UI to
perform the following actions:

1. Add a *User* with the username ``alice``.
2. Add a *User Group* for system administrators named ``sysadmin``.
3. Add ``alice`` to the ``sysadmin`` group.


CLI
---

Make sure you have a Kerberos ticket for ``admin`` (reminder:
``kinit admin``).

Most FreeIPA administrative actions can be carried out using the
``ipa`` CLI program.  Let's see what commands are available::

  [server]% ipa help commands
  automember-add                    Add an automember rule.
  automember-add-condition          Add conditions to an automember rule.
  automember-default-group-remove   Remove default (fallback) group for all unmatched entries.
  automember-default-group-set      Set default (fallback) group for all unmatched entries.
  automember-default-group-show     Display information about the default (fallback) automember groups.
  ...

Whoa!  There are nearly 400 commands!  We'll be using only a handful
of these today.  Note that command completion is enabled in the
shell, so you can type a partial command and press ``<TAB>`` a
couple of times to see what commands are available, e.g. all the
commands starting with ``cert-``::

  [server]$ ipa cert-<TAB>
  cert-find         cert-request      cert-show
  cert-remove-hold  cert-revoke       cert-status


You'll notice that commands are grouped by *topic*, or the kind of
object they act upon.  Run ``ipa help topics`` to list all topics.
You can read a general overview of a topic by running ``ipa help
<topic>``, and specific information on a particular command by
running ``ipa help <command>``.

Add a user named ``bob`` from the CLI. Use the CLI help to find the
right command (**hint**: the ``user`` plugin provides the command).


User authentication
-------------------

We have seen how to authenticate as ``admin``.  The process is the
same for regular users - just ``kinit <username>``!

Try to authenticate as ``bob``::

  [server]$ kinit bob
  kinit: Pre-authentication failed: Invalid argument while getting initial credentials

If you did *not* encounter this error, congratulations - you must be
a disciplined reader of documentation!  To set an initial password
when creating a user via the ``ipa user-add`` command you must
supply the ``--password`` flag (the command will prompt for the
password).

Use the ``ipa passwd`` command to (re)set a user's password::

  [server]$ ipa passwd bob
  New Password:
  Enter New Password again to verify:
  ----------------------------------------
  Changed password for "bob@IPADEMO.LOCAL"
  ----------------------------------------

Whenever a user has their password reset (including the first time
it is set), the next ``kinit`` will prompt them to enter a new
password::

  [server]$ kinit bob
  Password for bob@IPADEMO.LOCAL:
  Password expired.  You must change it now.
  Enter new password:
  Enter it again:


Now ``bob`` has a TGT (run ``klist`` to confirm) which he can use to
authenticate himself to other hosts and services.  Try logging into
``client.ipademo.local``::

  [server]$ ssh bob@client.ipademo.local
  Creating home directory for bob.
  [bob@client]$

You are now logged into the client as ``bob``.  Type ``^D`` or
``exit`` to log out and return to the ``server`` shell.  If you run
``klist`` again, you will see not only the TGT but a *service ticket*
that was automatically acquired to log in to
``client.ipademo.local`` without prompting for a password.  Kerberos
is a true *single sign-on* protocol!

::

  [server]$ klist
  Ticket cache: KEYRING:persistent:1000:1000
  Default principal: bob@IPADEMO.LOCAL

  Valid starting       Expires              Service principal
  06/04/2018 21:45:50  06/05/2018 21:38:24  host/client.ipademo.local@IPADEMO.LOCAL
  06/04/2018 21:38:41  06/05/2018 21:38:24  krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL


Now that you have created some users, it's time to define some
access policies.  Proceed to
:ref:`Unit 4: Host-based access control (HBAC) <4-hbac>`.

Alternatively, if you are interested in SSH public key management
for users and hosts, jump ahead to
:ref:`Unit 10: SSH user and host key management <10-ssh-key-management>`.
