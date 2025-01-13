.. _4-hbac:

Unit 4: Host-based access control (HBAC)
==========================================

**Prerequisites:**

- :ref:`Unit 3: User management and Kerberos authentication <3-user-management>`

FreeIPA's *host-based access control* (HBAC) feature allows you to
define policies that restrict access to hosts or services based on
the user attempting to log in and that user's groups, the host that
they are trying to access (or its *Host Groups*), and (optionally)
the service being accessed.

In this unit, we will define an HBAC policy that restricts
login access to ``client.ipademo.local`` to members of the
``sysadmin`` user group.


Adding a host group
-------------------

Instead of defining the HBAC rule to directly talk about
``client.ipademo.local``, create a *Host Group* named ``webservers``
and add ``client.ipademo.local`` to it.  You can do this via the Web
UI or the ``ipa`` CLI program (don't forget to ``kinit admin``; see
if you can work out what plugin provides the host group
functionality).

**Hint:** if you use the CLI will need to run two separate
commands—one to create the host group, then another to add
``client.ipademo.local`` to the host group.


Disabling the ``allow_all`` HBAC rule
-------------------------------------

HBAC rules are managed via the ``hbacrule`` plugin.  You can
complete the following actions via the Web UI as well, but we will
cover the CLI commands.

List the existing HBAC rules::

  [server]$ ipa hbacrule-find
  -------------------
  1 HBAC rule matched
  -------------------
    Rule name: allow_all
    User category: all
    Host category: all
    Service category: all
    Description: Allow all users to access any host from any host
    Enabled: TRUE

    Rule name: allow_systemd-user
    User category: all
    Host category: all
    Description: Allow pam_systemd to run user@.service to create a system user session
    Enabled: True
  ----------------------------
  Number of entries returned 2
  ----------------------------

The FreeIPA server is installed with a single default ``allow_all``
rule.  This rule must be disabled for other HBAC rules to take
effect.  Look for a command that can do this, and run it.


Creating HBAC rules
-------------------

HBAC rules are built up incrementally.  The rule is created, then
users or groups, hosts or hostgroups and HBAC services are added to
the rule.  The following transcript details the process::

  [server]$ ipa hbacrule-add sysadmin_webservers
  -------------------------------------
  Added HBAC rule "sysadmin_webservers"
  -------------------------------------
    Rule name: sysadmin_webservers
    Enabled: TRUE

  [server]$ ipa hbacrule-add-host sysadmin_webservers --hostgroup webservers
    Rule name: sysadmin_webservers
    Enabled: TRUE
    Host Groups: webservers
  -------------------------
  Number of members added 1
  -------------------------

  [server]$ ipa hbacrule-add-user sysadmin_webservers --group sysadmin
    Rule name: sysadmin_webservers
    Enabled: TRUE
    User Groups: sysadmin
    Host Groups: webservers
  -------------------------
  Number of members added 1
  -------------------------

  [server]$ ipa hbacrule-mod sysadmin_webservers --servicecat=all
  ----------------------------------------
  Modified HBAC rule "sysadmin_webservers"
  ----------------------------------------
    Rule name: sysadmin_webservers
    Service category: all
    Enabled: TRUE
    User Groups: sysadmin
    Host Groups: webservers

The ``--servicecat=all`` option applies this rule for all services on
matching hosts.  It could have been set during the ``hbacrule-add``
command instead.


Testing HBAC rules
------------------

You can test HBAC rule evaluation using the ``ipa hbactest``
command::

  [server]$ ipa hbactest --host client.ipademo.local --service sshd --user bob
  ---------------------
  Access granted: False
  ---------------------
    Not matched rules: sysadmin_webservers

Poor ``bob``.  He won't be allowed in because he is not a member of
the ``sysadmin`` group.  What is the result of ``ipa hbactest`` for
``alice``?

``kinit`` as ``bob`` and try to log in to the client::

  [server]$ kinit bob
  Password for bob@IPADEMO.LOCAL:
  [server]$ ssh bob@client.ipademo.local
  Connection closed by UNKNOWN port 65535

The server refused to let ``bob`` in and closed the connection.

Now try ``alice``::

  [server]$ kinit alice
  Password for alice@IPADEMO.LOCAL:
  [server]$ ssh alice@client.ipademo.local
  Creating home directory for alice.
  [alice@client]$


This was the final mandatory unit in the workshop.  From here, there
are several optional units you can choose from.  You can proceed
directly to
:ref:`Unit 5: Web application authentication and authorisation <5-web-app-authnz>`.
Otherwise,
:ref:`return to the curriculum overview <curriculum-overview>`
to see all the options.
