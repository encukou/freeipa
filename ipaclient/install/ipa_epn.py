#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
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

"""This tool prepares then sends email notifications to users
   whose passwords are expiring in the near future.
"""


from __future__ import absolute_import, print_function

import ast
import grp
import json
import os
import pwd
import logging
import smtplib
import ssl
import time

from collections import deque
from datetime import datetime, timedelta, timezone
UTC = timezone.utc
from email.utils import formataddr, formatdate
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email.utils import make_msgid
from socket import error as socketerror

from ipaplatform.paths import paths
from ipalib import api, errors
from ipalib.facts import is_ipa_client_configured
from ipapython import admintool, ipaldap
from ipapython.dn import DN

from jinja2 import Environment, FileSystemLoader, TemplateSyntaxError


EPN_CONF = "/etc/ipa/epn.conf"
EPN_CONFIG = {
    "smtp_server": "localhost",
    "smtp_port": 25,
    "smtp_user": None,
    "smtp_password": None,
    "smtp_client_cert": None,
    "smtp_client_key": None,
    "smtp_client_key_pass": None,
    "smtp_timeout": 60,
    "smtp_security": "none",
    "smtp_admin": "root@localhost",
    "smtp_delay": None,
    "mail_from": None,
    "mail_from_name": "IPA-EPN",
    "notify_ttls": "28,14,7,3,1",
    "msg_charset": "utf8",
    "msg_subtype": "plain",
    "msg_subject": "Your password will expire soon.",
}

logger = logging.getLogger(__name__)


def drop_privileges(new_username="daemon", new_groupname="daemon"):
    """Drop privileges, defaults to daemon:daemon.
    """
    try:
        if os.getuid() != 0:
            return

        os.setgroups([])
        os.setgid(pwd.getpwnam(new_username).pw_uid)
        os.setuid(grp.getgrnam(new_groupname).gr_gid)

        if os.getuid() == 0:
            raise errors.RequiresRoot("Cannot drop privileges!")

        logger.debug(
            "Dropped privileges to user=%s, group=%s",
            new_username,
            new_groupname,
        )

    except Exception as e:
        logger.error(
            "Failed to drop privileges to %s, %s: %s",
            new_username,
            new_groupname,
            e,
        )


class EPNUserList:
    """Maintains a list of users whose passwords are expiring.
       Provides add(), check(), pop(), and json_print().
       From the outside, the list is considered always sorted:
       * displaying the list results in a sorted JSON representation thereof
       * pop() returns the "most urgent" item from the list.
       Internal implementation notes:
       * Uses a deque instead of a list for efficiency reasons
       * all add()-style methods MUST set _sorted to False.
       * all print() and pop-like methods MUST call _sort() first.
    """

    def __init__(self):
        self._sorted = False
        self._expiring_password_user_dq = deque()

    def __bool__(self):
        """If it quacks like a container...
        """
        return bool(self._expiring_password_user_dq)

    def __len__(self):
        """Return len(self)."""
        return len(self._expiring_password_user_dq)

    def get_ldap_attr(self, entry, attr):
        """Get a single value from a multi-valued attr in a safe way"""
        return str(entry.get(attr, [""]).pop(0))

    def add(self, entry):
        """Parses and appends an LDAP user entry with the uid, cn,
           givenname, sn, krbpasswordexpiration and mail attributes.
        """
        try:
            self._sorted = False
            if entry.get("mail") is None:
                logger.error("IPA-EPN: No mail address defined for: %s",
                             entry.dn)
                return
            self._expiring_password_user_dq.append(
                dict(
                    uid=self.get_ldap_attr(entry, "uid"),
                    cn=self.get_ldap_attr(entry, "cn"),
                    givenname=self.get_ldap_attr(entry, "givenname"),
                    sn=self.get_ldap_attr(entry, "sn"),
                    krbpasswordexpiration=(
                        self.get_ldap_attr(entry,"krbpasswordexpiration")
                    ),
                    mail=str(entry.get("mail")),
                )
            )
        except IndexError as e:
            logger.info("IPA-EPN: Could not parse entry: %s", e)

    def pop(self):
        """Returns the "most urgent" user to notify.
           In fact: popleft()
        """
        self._sort()
        try:
            return self._expiring_password_user_dq.popleft()
        except IndexError:
            return False

    def check(self):
        self.json_print(really_print=False)

    def json_print(self, really_print=True):
        """Dump self._expiring_password_user_dq to JSON.
           Check that the result can be re-rencoded to UTF-8.
           If really_print, print the result.
        """
        try:
            self._sort()
            temp_str = json.dumps(
                list(self._expiring_password_user_dq),
                indent=4,
                ensure_ascii=False,
            )
            temp_str.encode("utf8")
            if really_print:
                print(temp_str)
        except Exception as e:
            logger.error("IPA-EPN: unexpected error: %s", e)

    def _sort(self):
        if not self._sorted:
            if isinstance(self._expiring_password_user_dq, deque):
                self._expiring_password_user_dq = deque(
                    sorted(
                        self._expiring_password_user_dq,
                        key=lambda item: item["krbpasswordexpiration"],
                    )
                )
                self._sorted = True


class EPN(admintool.AdminTool):
    command_name = "IPA-EPN"
    log_file_name = paths.IPAEPN_LOG

    usage = "%prog [options]"
    description = "Expiring Password Notifications (EPN)"

    def __init__(self, options, args):
        super(EPN, self).__init__(options, args)
        self._conn = None
        self._ssl_context = None
        self._expiring_password_user_list = EPNUserList()
        self._ldap_data = []
        self._date_ranges = []
        self._mailer = None
        self.env = None
        self.default_email_domain = None

    @classmethod
    def add_options(cls, parser):
        super(EPN, cls).add_options(parser, debug_option=True)
        parser.add_option(
            "--from-nbdays",
            dest="from_nbdays",
            action="store",
            default=None,
            help="minimal number of days",
        )
        parser.add_option(
            "--to-nbdays",
            dest="to_nbdays",
            action="store",
            default=None,
            help="maximal number of days",
        )
        parser.add_option(
            "--dry-run",
            dest="dry_run",
            action="store_true",
            default=False,
            help="Dry run mode. JSON ouput only.",
        )
        parser.add_option(
            "--mail-test",
            dest="mailtest",
            action="store_true",
            default=False,
            help="Send a test e-mail",
        )

    def validate_options(self):
        super(EPN, self).validate_options(needs_root=True)
        if self.options.to_nbdays is not None:
            try:
                if int(self.options.to_nbdays) < 0:
                    raise RuntimeError('Input is negative.')
            except Exception as e:
                self.option_parser.error(
                    "--to-nbdays must be a positive integer. "
                    "{error}".format(error=e)
                )
            self.options.dry_run = True
        if self.options.from_nbdays is not None:
            try:
                if int(self.options.from_nbdays) < 0:
                    raise RuntimeError('Input is negative.')
            except Exception as e:
                self.option_parser.error(
                    "--from-nbdays must be a positive integer. "
                    "{error}".format(error=e)
                )
        if self.options.from_nbdays is not None and \
                self.options.to_nbdays is not None:
            if int(self.options.from_nbdays) >= int(self.options.to_nbdays):
                self.option_parser.error(
                    "--from-nbdays must be smaller than --to-nbdays."
                )
        if self.options.from_nbdays is not None and \
                self.options.to_nbdays is None:
            self.option_parser.error(
                "You cannot specify --from-nbdays without --to-nbdays"
            )
        if self.options.mailtest and self.options.dry_run:
            self.option_parser.error(
                "You cannot specify --mail-test and --dry-run together"
            )

    def setup_logging(self, log_file_mode="a"):
        super(EPN, self).setup_logging(log_file_mode="a")

    def run(self):
        super(EPN, self).run()

        if not is_ipa_client_configured():
            logger.error("IPA client is not configured on this system.")
            raise admintool.ScriptError()

        # tasks required privileges
        self._get_krb5_ticket()
        self._read_configuration()
        self._validate_configuration()
        self._parse_configuration()
        self._get_connection()
        self._read_ipa_configuration()
        self._create_ssl_context()

        drop_privileges()
        if self.options.mailtest:
            self._gentestdata()
        else:
            if self.options.to_nbdays:
                self._build_cli_date_ranges()
            for date_range in self._date_ranges:
                self._fetch_data_from_ldap(date_range)
                self._parse_ldap_data()
        if self.options.dry_run:
            self._pretty_print_data()
        else:
            self._mailer = MailUserAgent(
                security_protocol=api.env.smtp_security,
                smtp_hostname=api.env.smtp_server,
                smtp_port=api.env.smtp_port,
                smtp_timeout=api.env.smtp_timeout,
                smtp_username=api.env.smtp_user,
                smtp_password=api.env.smtp_password,
                ssl_context=self._ssl_context,
                x_mailer=self.command_name,
                msg_subtype=api.env.msg_subtype,
                msg_charset=api.env.msg_charset,
            )
            self._send_emails()

    def _get_date_range_from_nbdays(self, nbdays_end, nbdays_start=None):
        """Detects current time and returns a date range, given a number
           of days in the future.
           If only nbdays_end is specified, the range is 1d long.
        """
        now = datetime.now(tz=UTC)
        today_at_midnight = datetime.combine(now, datetime.min.time())
        range_end = today_at_midnight + timedelta(days=nbdays_end)
        if nbdays_start is not None:
            range_start = today_at_midnight + timedelta(days=nbdays_start)
        else:
            range_start = range_end - timedelta(days=1)

        logger.debug(
            "IPA-EPN: Current date: %s \n"
            "IPA-EPN: Date & time, today at midnight: %s \n"
            "IPA-EPN: Date range start: %s \n"
            "IPA-EPN: Date range end: %s \n",
            now,
            today_at_midnight,
            range_start,
            range_end,
        )
        return (range_start, range_end)

    def _datetime_to_generalized_time(self, dt):
        """Convert datetime to LDAP_GENERALIZED_TIME_FORMAT
           Note: Consider moving into ipalib.
        """
        dt = dt.timetuple()
        generalized_time_str = str(dt.tm_year) + "".join(
            "0" * (2 - len(str(item))) + str(item)
            for item in (
                dt.tm_mon,
                dt.tm_mday,
                dt.tm_hour,
                dt.tm_min,
                dt.tm_sec,
            )
        )
        return generalized_time_str + "Z"

    def _get_krb5_ticket(self):
        """Setup the environment to obtain a krb5 ticket for us using the
           system keytab.
           Uses CCACHE = MEMORY (limited to the current process).
        """
        os.environ.setdefault("KRB5_CLIENT_KTNAME", "/etc/krb5.keytab")
        os.environ["KRB5CCNAME"] = "MEMORY:"

    def _read_configuration(self):
        """Merge in the EPN configuration from /etc/ipa/epn.conf"""
        base_config = dict(
            context="epn", confdir=paths.ETC_IPA, in_server=False,
        )
        api.bootstrap(**base_config)
        api.env._merge(**EPN_CONFIG)

        if not api.isdone("finalize"):
            api.finalize()

    def _validate_configuration(self):
        """Examine the user-provided configuration.
        """
        if api.env.smtp_security.lower() not in ("none", "starttls", "ssl"):
            raise RuntimeError(
                "smtp_security must be one of: none, starttls or ssl"
            )
        if api.env.smtp_user is not None and api.env.smtp_password is None:
            raise RuntimeError("smtp_user set and smtp_password is not")
        if api.env.notify_ttls is None:
            raise RuntimeError("notify_ttls must be set in %s" % EPN_CONF)
        try:
            [int(k) for k in str(api.env.notify_ttls).split(',')]
        except ValueError as e:
            raise RuntimeError('Failed to parse notify_ttls: \'%s\': %s' %
                               (api.env.notify_ttls, e))
        if api.env.smtp_delay:
            try:
                float(api.env.smtp_delay)
            except ValueError as e:
                raise RuntimeError('smtp_delay is misformatted: %s' % e)
            if float(api.env.smtp_delay) < 0:
                raise RuntimeError('smtp_delay cannot be less than zero')

    def _parse_configuration(self):
        """
        """
        daylist = [int(k) for k in str(api.env.notify_ttls).split(',')]
        daylist.sort()

        for day in daylist:
            self._date_ranges.append(
                self._get_date_range_from_nbdays(
                    nbdays_start=None, nbdays_end=day + 1
                )
            )

        loader = FileSystemLoader(os.path.join(api.env.confdir, 'epn'))
        self.env = Environment(loader=loader)

    def _read_ipa_configuration(self):
        """Get the IPA configuration"""
        api.Backend.rpcclient.connect()
        result = api.Command.config_show()['result']
        self.default_email_domain = result.get('ipadefaultemaildomain',
                                               [None])[0]
        api.Backend.rpcclient.disconnect()

    def _get_connection(self):
        """Create a connection to LDAP and bind to it.
        """
        if self._conn is not None:
            return self._conn

        try:
            # LDAPI
            self._conn = ipaldap.LDAPClient.from_realm(api.env.realm)
            self._conn.external_bind()
        except Exception:
            try:
                # LDAP + GSSAPI
                self._conn = ipaldap.LDAPClient.from_hostname_secure(
                    api.env.server
                )
                self._conn.gssapi_bind()
            except Exception as e:
                logger.error(
                    "Unable to bind to LDAP server %s: %s",
                    self._conn.ldap_uri,
                    e,
                )

        return self._conn

    def _create_ssl_context(self):
        """Create SSL context.
           This must be done before the dropping priviliges to allow
           read in the smtp client's certificate and private key if specified.
        """
        if api.env.smtp_security.lower() in ("starttls", "ssl"):
            self._ssl_context = ssl.create_default_context()
            if api.env.smtp_client_cert:
                self._ssl_context.load_cert_chain(
                    certfile=api.env.smtp_client_cert,
                    keyfile=api.env.smtp_client_key,
                    password=str(api.env.smtp_client_key_pass),
                )

    def _fetch_data_from_ldap(self, date_range):
        """Run a LDAP query to fetch a list of user entries whose passwords
           would expire in the near future. Store in self._ldap_data.
        """

        if self._conn is None:
            logger.error(
                "IPA-EPN: Connection to LDAP not established. Exiting."
            )

        search_base = DN(api.env.container_user, api.env.basedn)
        attrs_list = ["uid", "krbpasswordexpiration", "mail", "cn",
                      "givenname", "surname"]

        search_filter = (
            "(&(!(nsaccountlock=TRUE)) \
            (krbpasswordexpiration<=%s) \
            (krbpasswordexpiration>=%s))"
            % (
                self._datetime_to_generalized_time(date_range[1]),
                self._datetime_to_generalized_time(date_range[0]),
            )
        )

        try:
            self._ldap_data = self._conn.get_entries(
                search_base,
                filter=search_filter,
                attrs_list=attrs_list,
                scope=self._conn.SCOPE_SUBTREE,
            )
        except errors.EmptyResult:
            logger.debug("Empty Result.")
        finally:
            logger.debug("%d entries found", len(self._ldap_data))

    def _parse_ldap_data(self):
        """Fill out self._expiring_password_user_list from data from ldap.
        """
        if self._ldap_data:
            for entry in self._ldap_data:
                self._expiring_password_user_list.add(entry)
            # Validate json.
            try:
                self._pretty_print_data(really_print=False)
            except Exception as e:
                logger.error("IPA-EPN: Could not create JSON: %s", e)
            finally:
                self._ldap_data = []

    def _pretty_print_data(self, really_print=True):
        """Dump self._expiring_password_user_list to JSON.
        """
        self._expiring_password_user_list.json_print(
            really_print=really_print
        )

    def _send_emails(self):
        if self._mailer is None:
            logger.error("IPA-EPN: mailer was not configured.")
            return
        else:
            try:
                template = self.env.get_template("expire_msg.template")
            except TemplateSyntaxError as e:
                raise RuntimeError("Parsing template %s failed: %s" %
                                   (e.filename, e))
            if api.env.mail_from:
                mail_from = api.env.mail_from
            else:
                mail_from = "noreply@%s" % self.default_email_domain
            now = datetime.now(tz=UTC)
            while self._expiring_password_user_list:
                entry = self._expiring_password_user_list.pop()
                expdate = datetime.strptime(
                    entry["krbpasswordexpiration"],
                    '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC)
                expdelta = expdate - now
                body = template.render(
                    uid=entry["uid"],
                    first=entry["givenname"],
                    last=entry["sn"],
                    fullname=entry["cn"],
                    expiration=entry["krbpasswordexpiration"],
                    expiration_datetime=expdate,
                    expiration_delta=expdelta,
                )
                self._mailer.send_message(
                    mail_subject=api.env.msg_subject,
                    mail_body=body,
                    subscribers=ast.literal_eval(entry["mail"]),
                    mail_from=mail_from,
                    mail_from_name=api.env.mail_from_name,
                )
                logger.debug(
                    "Notified %s (%s). Password expiring in %d days at %s.",
                    entry["mail"], entry["uid"], expdelta.days,
                    expdate)
                if api.env.smtp_delay:
                    time.sleep(float(api.env.smtp_delay) / 1000)
            self._mailer.cleanup()

    def _gentestdata(self):
        """Generate a sample user to process through the template.
        """
        expdate = datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S')
        entry = dict(
            uid=["SAUSER"],
            cn=["SAMPLE USER"],
            givenname=["SAMPLE"],
            sn=["USER"],
            krbpasswordexpiration=[expdate],
            mail=[api.env.smtp_admin],
        )
        self._expiring_password_user_list.add(entry)

    def _build_cli_date_ranges(self):
        """When self.options.to_nbdays is set, override the date ranges read
           from the configuration file and build the date ranges from the CLI
           options.
        """
        self._date_ranges = []
        logger.debug("IPA-EPN: Ignoring configuration file ranges.")
        if self.options.from_nbdays is not None:
            self._date_ranges.append(
                self._get_date_range_from_nbdays(
                    nbdays_start=int(self.options.from_nbdays),
                    nbdays_end=int(self.options.to_nbdays),
                )
            )
        elif self.options.to_nbdays is not None:
            self._date_ranges.append(
                self._get_date_range_from_nbdays(
                    nbdays_start=None, nbdays_end=int(self.options.to_nbdays)
                )
            )


class MTAClient:
    """MTA Client class. Originally done for EPN.
    """

    def __init__(
        self,
        security_protocol="none",
        smtp_hostname="localhost",
        smtp_port=25,
        smtp_timeout=60,
        smtp_username=None,
        smtp_password=None,
        ssl_context=None,
    ):
        self._security_protocol = security_protocol
        self._smtp_hostname = smtp_hostname
        self._smtp_port = smtp_port
        self._smtp_timeout = smtp_timeout
        self._username = smtp_username
        self._password = smtp_password
        self._ssl_context = ssl_context

        # This should not be touched
        self._conn = None

        if (
            self._security_protocol == "none"
            and "localhost" not in self._smtp_hostname
        ):
            logger.error(
                "IPA-EPN: using cleartext for non-localhost SMTPd "
                "is not supported."
            )

        self._connect()

    def cleanup(self):
        self._disconnect()

    def send_message(self, message_str=None, subscribers=None):
        result = None
        try:
            result = self._conn.sendmail(
                api.env.smtp_admin, subscribers, message_str,
            )
        except Exception as e:
            logger.info("IPA-EPN: Failed to send mail: %s", e)
        finally:
            if result:
                for key in result:
                    logger.info(
                        "IPA-EPN: Failed to send mail to '%s': %s %s",
                        key,
                        result[key][0],
                        result[key][1],
                    )
                logger.info(
                    "IPA-EPN: Failed to send mail to at least one recipient"
                )

    def _connect(self):
        try:
            if self._security_protocol.lower() in ["none", "starttls"]:
                self._conn = smtplib.SMTP(
                    host=self._smtp_hostname,
                    port=self._smtp_port,
                    timeout=self._smtp_timeout,
                )
            else:
                self._conn = smtplib.SMTP_SSL(
                    host=self._smtp_hostname,
                    port=self._smtp_port,
                    timeout=self._smtp_timeout,
                    context=self._ssl_context,
                )
        except (socketerror, smtplib.SMTPException) as e:
            msg = \
                "IPA-EPN: Could not connect to the configured SMTP server: " \
                "{host}:{port}: {error}".format(
                    host=self._smtp_hostname,
                    port=self._smtp_port,
                    error=e
                )
            raise admintool.ScriptError(msg)

        try:
            self._conn.ehlo()
        except smtplib.SMTPException as e:
            logger.error(
                "IPA-EPN: EHLO failed for host %s:%s: %s",
                self._smtp_hostname,
                self._smtp_port,
                e,
            )

        if self._security_protocol.lower() == "starttls":
            try:
                self._conn.starttls(context=self._ssl_context)
                self._conn.ehlo()
            except smtplib.SMTPException as e:
                raise RuntimeError(
                    "IPA-EPN: Unable to create an encrypted session to "
                    "%s:%s: %s" % (self._smtp_hostname, self._smtp_port, e)
                )

        if self._username and self._password:
            if self._conn.has_extn("AUTH"):
                try:
                    self._conn.login(self._username, self._password)
                    if self._security_protocol == "none":
                        logger.warning(
                            "IPA-EPN: Username and Password "
                            "were sent in the clear."
                        )
                except smtplib.SMTPAuthenticationError:
                    raise RuntimeError(
                        "IPA-EPN: Authentication to %s:%s failed, "
                        "please check your username and/or password:" %
                        (self._smtp_hostname,
                         self._smtp_port,)
                    )
                except smtplib.SMTPException as e:
                    raise RuntimeError(
                        "IPA-EPN: SMTP Error at %s:%s:%s" %
                        (self._smtp_hostname,
                         self._smtp_port,
                         e,)
                    )
            else:
                err_str = (
                    "IPA-EPN: Server at %s:%s "
                    "does not support authentication." %
                    (self._smtp_hostname,
                     self._smtp_port,)
                )
                logger.error(err_str)

    def _disconnect(self):
        self._conn.quit()


class MailUserAgent:
    """The MUA class for EPN.
    """

    def __init__(
        self,
        security_protocol="none",
        smtp_hostname="localhost",
        smtp_port=25,
        smtp_timeout=60,
        smtp_username=None,
        smtp_password=None,
        ssl_context=None,
        x_mailer=None,
        msg_subtype="plain",
        msg_charset="utf8",
    ):

        self._x_mailer = x_mailer
        self._subject = None
        self._body = None
        self._subscribers = None

        self._subtype = msg_subtype
        self._charset = msg_charset

        self._msg = None
        self._message_str = None

        self._mta_client = MTAClient(
            security_protocol=security_protocol,
            smtp_hostname=smtp_hostname,
            smtp_port=smtp_port,
            smtp_timeout=smtp_timeout,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            ssl_context=ssl_context,
        )

    def cleanup(self):
        self._mta_client.cleanup()

    def send_message(
        self, mail_subject=None, mail_body=None, subscribers=None,
        mail_from=None, mail_from_name=None
    ):
        """Given mail_subject, mail_body, and subscribers, composes
           the message and sends it.
        """
        if None in [mail_subject, mail_body, subscribers,
                    mail_from, mail_from_name]:
            logger.error("IPA-EPN: Tried to send an empty message.")
            return False
        self._compose_message(
            mail_subject=mail_subject,
            mail_body=mail_body,
            subscribers=subscribers,
            mail_from=mail_from,
            mail_from_name=mail_from_name,
        )
        self._mta_client.send_message(
            message_str=self._message_str, subscribers=subscribers
        )
        return True

    def _compose_message(
        self, mail_subject, mail_body, subscribers,
        mail_from, mail_from_name
    ):
        """The composer creates a MIME multipart message.
        """

        self._subject = mail_subject
        self._body = mail_body
        self._subscribers = subscribers

        self._msg = MIMEMultipart(_charset=self._charset)
        self._msg["From"] = formataddr((mail_from_name, mail_from))
        self._msg["To"] = ", ".join(self._subscribers)
        self._msg["Date"] = formatdate(localtime=True)
        self._msg["Subject"] = Header(self._subject, self._charset)
        self._msg["Message-Id"] = make_msgid()
        self._msg.preamble = "Multipart message"
        if "X-Mailer" not in self._msg and self._x_mailer:
            self._msg.add_header("X-Mailer", self._x_mailer)
        self._msg.attach(
            MIMEText(
                self._body + "\n\n",
                _subtype=self._subtype,
                _charset=self._charset,
            )
        )
        self._message_str = self._msg.as_string()
