.. _5-web-app-authnz:

Unit 5: Web application authentication and authorisation
==========================================================

**Prerequisites**:

- :ref:`Unit 3: User management and Kerberos authentication <3-user-management>`
- :ref:`Unit 4: Host-based access control (HBAC) <4-hbac>`

You can configure many kinds of applications to rely on FreeIPA's
centralised authentication, including web applications.  In this
unit you will configure the Apache web server to use Kerberos
authentication to authenticate users, PAM to enforce HBAC rules, and
``mod_lookup_identity`` to populate the request environment with
user attributes.

All activities in this unit take place on ``client`` unless
otherwise specified.  **Access the host via ``podman exec -it client bash``**
to ensure you have ``sudo`` access.

The demo web application is trivial.  It just reads its request
environment and responds in plain text with a list of variables
starting with the string ``"REMOTE_"``.  It should be up and running
already::

  [client]$ curl http://client.ipademo.local
  NOT LOGGED IN

  REMOTE_* REQUEST VARIABLES:

    REMOTE_ADDR: 192.168.33.20
    REMOTE_PORT: 34356


Create a service
----------------

Create a *service* representing the web application on
``client.ipademo.local``.  A service principal name has the service
type as its first part, separated from the host name by a slash,
e.g.  ``HTTP/www.example.com``.  The host part must be a host
enrolled in FreeIPA.

You must be getting the hang of FreeIPA by now, so I'll leave the
rest of this step up to you.  (It's OK to ask for help!)


Retrieve Kerberos keytab
------------------------

The service needs access to its Kerberos key in order to
authenticate users.  Retrieve the key from the FreeIPA server and
store it in a *keytab* file (you will need a TGT for ``admin``)::

  [client]$ ipa-getkeytab -p HTTP/client.ipademo.local -k app.keytab
  Keytab successfully retrieved and stored in: app.keytab

We also have to move the file, change its ownership and apply the
proper SELinux labels to the keytab file so that the Apache process
which runs under the confined ``apache`` user may read it::

  [client]$ mv app.keytab /etc/httpd
  [client]$ chown apache:apache /etc/httpd/app.keytab
  [client]$ restorecon /etc/httpd/app.keytab


Enable Kerberos authentication
------------------------------

In this section we will use mod_auth_gssapi_ to enable Kerberos
Negotiate / SPNEGO authentication for a web application.

.. _mod_auth_gssapi: https://github.com/modauthgssapi/mod_auth_gssapi

The Apache configuration for the demo application lives in the file
``/etc/httpd/conf.d/app.conf``.  Update the configuration (use
``vi`` or ``nano``) to enable Kerberos authentication::

  <VirtualHost *:80>
    ServerName client.ipademo.local
    WSGIScriptAlias / /usr/share/httpd/app.py

    <Location />
      AuthType GSSAPI
      AuthName "Kerberos Login"
      GssapiCredStore keytab:/etc/httpd/app.keytab
      Require valid-user
    </Location>

    <Directory /usr/share/httpd>
      <Files "app.py">
        Require all granted
      </Files>
    </Directory>
  </VirtualHost>


When the configuration is in place, restart Apache::

  [client]$ sudo systemctl restart httpd


To test that Kerberos Negotiate authentication is working, ``kinit``
and make a request using ``curl``::

  [client]$ kinit bob
  Password for bob@IPADEMO.LOCAL:

  [client]$ curl -u : --negotiate http://client.ipademo.local/
  LOGGED IN AS: bob@IPADEMO.LOCAL

  REMOTE_* REQUEST VARIABLES:

    REMOTE_ADDR: 192.168.33.20
    REMOTE_USER: bob@IPADEMO.LOCAL
    REMOTE_PORT: 42499

The ``REMOTE_USER`` variable in the request environment indicates
that there is an authenticated user, and identifies that user.


Populating request environment with user attributes
----------------------------------------------------

Applications need to know more than just the username of a logged-in
user.  They want to know the user's name, to send mail to their email
address and perhaps to know their group memberships or other
attributes.  In this section, we will use mod_lookup_identity_ to
populate the HTTP request environment with variables providing
information about the authenticated user.

.. _mod_lookup_identity: https://www.adelton.com/apache/mod_lookup_identity/

``mod_lookup_identity`` retrieves user attributes from SSSD (via D-Bus).
Edit ``/etc/sssd/sssd.conf``; enable the SSSD ``ifp`` *InfoPipe*
responder, permit the ``apache`` user to query it, and configure the
attributes that you want to expose.  Add the following configuration to
``sssd.conf``::

  [domain/ipademo.local]
  ...
  ldap_user_extra_attrs = mail, givenname, sn

  [sssd]
  services = nss, sudo, pam, ssh, ifp
  ...

  [ifp]
  allowed_uids = apache, root
  user_attributes = +mail, +givenname, +sn


Restart SSSD::

  [client]$ systemctl restart sssd

If you had not added an email address to your users when you created them, you will need to empty the SSSD cache::

  [client]$ sss_cache -E


You can test the SSSD InfoPipe directly via the ``dbus-send``
utility::

  [client]$ dbus-send --print-reply --system \
      --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe \
      org.freedesktop.sssd.infopipe.GetUserAttr string:alice array:string:mail
  method return time=1528050430.867333 sender=:1.147 -> destination=:1.150 serial=5 reply_serial=2
     array [
        dict entry(
           string "mail"
           variant             array [
                 string "alice@ipademo.local"
              ]
        )
     ]


Now update the Apache configuration to populate the request
environment.  The ``LookupUserXXX`` directives define the mapping of
user attributes to request environment variables.  Multi-valued
attributes can be expanded into multiple variables, as in the
``LookupUserGroupsIter`` directive.  Do not forget the
``LoadModule`` directive at the top!

::

  LoadModule lookup_identity_module modules/mod_lookup_identity.so

  <VirtualHost *:80>
    ServerName client.ipademo.local
    WSGIScriptAlias / /usr/share/httpd/app.py

    <Location />
      AuthType GSSAPI
      AuthName "Kerberos Login"
      GssapiCredStore keytab:/etc/httpd/app.keytab
      Require valid-user

      LookupUserAttr mail REMOTE_USER_MAIL
      LookupUserAttr givenname REMOTE_USER_FIRSTNAME
      LookupUserAttr sn REMOTE_USER_LASTNAME
      LookupUserGroupsIter REMOTE_USER_GROUP
    </Location>

    ...
  </VirtualHost>

Default SELinux policy prevents Apache from communicating with SSSD
over D-Bus.  Set ``httpd_dbus_sssd`` to ``1``::

  [client]$ sudo setsebool -P httpd_dbus_sssd 1

Restart Apache::

  [client]$ sudo systemctl restart httpd

Now make another request to the application and observe that user
information that was injected into the request environment by
``mod_lookup_identity`` is reflected in the response::

  [client]$ curl -u : --negotiate http://client.ipademo.local/
  LOGGED IN AS: alice@IPADEMO.LOCAL

  REMOTE_* REQUEST VARIABLES:

    REMOTE_USER_GROUP_N: 2
    REMOTE_ADDR: 192.168.33.20
    REMOTE_USER_FIRSTNAME: Alice
    REMOTE_USER_LASTNAME: Able
    REMOTE_USER: alice@IPADEMO.LOCAL
    REMOTE_USER_GROUP_2: ipausers
    REMOTE_USER_GROUP_1: sysadmin
    REMOTE_PORT: 42586
    REMOTE_USER_EMAIL: alice@ipademo.local


HBAC for web services
---------------------

The final task for this unit is to configure Apache to use FreeIPA's HBAC
rules for access control.  We will use mod_authnz_pam_ in
conjunction with SSSD's PAM responder to achieve this.

.. _mod_authnz_pam: http://www.adelton.com/apache/mod_authnz_pam/

First add an *HBAC service* named ``app`` for the web application.
You can do this as ``admin`` via the Web UI or CLI.  **Hint:** the
``hbacsvc`` plugin provides this functionality.

Next, add an HBAC rule allowing members of the ``sysadmin`` user
group access to ``app`` (on any host)::

  [client]$ ipa hbacrule-add --hostcat=all sysadmin_app
  ------------------------------
  Added HBAC rule "sysadmin_app"
  ------------------------------
    Rule name: sysadmin_app
    Host category: all
    Enabled: TRUE

  [client]$ ipa hbacrule-add-user sysadmin_app --group sysadmin
    Rule name: sysadmin_app
    Host category: all
    Enabled: TRUE
    User Groups: sysadmin
  -------------------------
  Number of members added 1
  -------------------------

  [client]$ ipa hbacrule-add-service sysadmin_app --hbacsvcs app
    Rule name: sysadmin_app
    Host category: all
    Enabled: TRUE
    User Groups: sysadmin
    Services: app
  -------------------------
  Number of members added 1
  -------------------------

Next, define the PAM service on ``client``.  The name must match the
``hbacsvc`` name (in our case: ``app``), and the name is indicated
by the *name of the file* that configures the PAM stack.  Create
``/etc/pam.d/app`` with the following contents::

  account required   pam_sss.so

Finally, update the Apache configuration.  Find the line::

  Require valid-user

Replace with::

  Require pam-account app

Also add the ``LoadModule`` directive to the top of the file::

  LoadModule authnz_pam_module modules/mod_authnz_pam.so

Once again, we must set a special SELinux boolean to allow
``mod_authnz_pam`` to work::

  [client]$ sudo setsebool -P allow_httpd_mod_auth_pam 1

Restart Apache and try and perform the same ``curl`` request again
as ``alice``.  Everything should work as before because ``alice`` is
a member of the ``sysadmin`` group.  What happens when you are
authenticated as ``bob`` instead?

This unit is now concluded.  Now that you have mastered web app
authentication, you'll want to configure TLS for your site.  Proceed
to
:ref:`Unit 6: Service certificates <6-cert-management>`.
