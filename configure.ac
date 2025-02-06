AC_PREREQ(2.59)
AC_CONFIG_MACRO_DIRS([m4])
m4_include(VERSION.m4)
AC_INIT([freeipa],
        IPA_VERSION,
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

dnl Make sure the build directory name does not contain spaces!
dnl Spaces are causing problems in libtool, makefiles, autoconf itself,
dnl gettextize framework etc.
case "$PWD" in
  *\ * | *\	*)
    AC_MSG_ERROR([whitespace in working directory path is not supported]) ;;
esac

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign 1.9 tar-pax])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

dnl enable C11 extensions for features like memset_s()
CFLAGS="$CFLAGS -D__STDC_WANT_LIB_EXT1__=1"
dnl enable features like htole16()
CFLAGS="$CFLAGS -D_DEFAULT_SOURCE=1"
dnl Enable features like strndup()
CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=200809L"
dnl fail hard when includes statements are missing
CFLAGS="$CFLAGS -Werror=implicit-function-declaration"

AC_PROG_CC_C99
AC_DISABLE_STATIC
LT_INIT

AC_HEADER_STDC

PKG_PROG_PKG_CONFIG

AC_ARG_ENABLE([server],
    [AC_HELP_STRING([--disable-server], [Disable server support])],
    [case "${enableval}" in
         yes) enable_server=yes ;;
          no) enable_server=no ;;
           *) AC_MSG_ERROR([bad value ${enableval} for --disable-server]) ;;
     esac],
    [enable_server=yes])
AM_CONDITIONAL([ENABLE_SERVER], [test x$enable_server = xyes])

AC_ARG_WITH([ipatests],
    [AC_HELP_STRING([--without-ipatests], [Build without ipatests])],
    [with_ipatests=${withval}],
    [with_ipatests=yes])
AM_CONDITIONAL([WITH_IPATESTS], [test x"$with_ipatests" = xyes])

AC_ARG_WITH([ipa_join_xml],
    [AC_HELP_STRING([--with-ipa-join-xml], [Use XML-RPC support in ipa-join])],
    [with_ipa_join_xml=${withval}],
    [with_ipa_join_xml=no])
AS_IF([test x"$with_ipa_join_xml" = xyes], [AC_DEFINE([WITH_IPA_JOIN_XML], [1],
    [ipa-join uses XML-RPC])])
AM_CONDITIONAL([WITH_IPA_JOIN_XML], [test x"$with_ipa_join_xml" = xyes])

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

dnl ---------------------------------------------------------------------------
dnl - Check for POPT
dnl ---------------------------------------------------------------------------

PKG_CHECK_MODULES([POPT], [popt])

dnl ---------------------------------------------------------------------------
dnl - Check for KRB5
dnl ---------------------------------------------------------------------------

PKG_CHECK_MODULES([KRB5], [krb5])
PKG_CHECK_MODULES([KRB5_GSSAPI], [krb5-gssapi])

AC_CHECK_HEADER(kdb.h, [], [AC_MSG_ERROR([kdb.h not found])])
AC_CHECK_MEMBER(
	[kdb_vftabl.free_principal],
	[AC_DEFINE([HAVE_KDB_FREEPRINCIPAL], [1],
		   [KDB driver API has free_principal callback])],
	[AC_MSG_NOTICE([KDB driver API has no free_principal callback])],
	[[#include <kdb.h>]])
AC_CHECK_MEMBER(
	[kdb_vftabl.free_principal_e_data],
	[AC_DEFINE([HAVE_KDB_FREEPRINCIPAL_EDATA], [1],
		   [KDB driver API has free_principal_e_data callback])],
	[AC_MSG_NOTICE([KDB driver API has no free_principal_e_data callback])],
	[[#include <kdb.h>]])

if test "x$ac_cv_member_kdb_vftabl_free_principal" = "xno" \
	-a "x$ac_cv_member_kdb_vftable_free_principal_e_data" = "xno" ; then
    AC_MSG_WARN([KDB driver API does not allow to free Kerberos principal data.])
    AC_MSG_WARN([KDB driver will leak memory on Kerberos principal use])
    AC_MSG_WARN([See https://github.com/krb5/krb5/pull/596 for details])
fi

dnl ---------------------------------------------------------------------------
dnl - Check for OpenLDAP SDK
dnl ---------------------------------------------------------------------------

SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$NSPR_CFLAGS $NSS_CFLAGS"
SAVE_LIBS="$LIBS"
LIBS=
AC_SEARCH_LIBS([ldap_search], [ldap_r ldap], [], [AC_MSG_ERROR([libldap or libldap_r not found])])
AC_SEARCH_LIBS([ber_peek_tag], [lber], [], [AC_MSG_ERROR([liblber not found])])
LDAP_LIBS="$LIBS"
LDAP_CFLAGS=""
LIBS="$SAVE_LIBS"
LDAP_CFLAGS=""
AC_SUBST(LDAP_LIBS)
AC_SUBST(LDAP_CFLAGS)

dnl ---------------------------------------------------------------------------
dnl - Check for resolv library
dnl ---------------------------------------------------------------------------

SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$NSPR_CFLAGS $NSS_CFLAGS"
AC_CHECK_LIB(resolv,main,RESOLV_LIBS=-lresolv)
AC_CHECK_HEADERS(resolv.h)
AC_SUBST(RESOLV_LIBS)

dnl ---------------------------------------------------------------------------
dnl - Check for OpenSSL Crypto library
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([CRYPTO], [libcrypto])

dnl ---------------------------------------------------------------------------
dnl - Check for pwquality library
dnl ---------------------------------------------------------------------------
AM_COND_IF([ENABLE_SERVER], [
	PKG_CHECK_MODULES([PWQUALITY], [pwquality],
		[AC_DEFINE(USE_PWQUALITY,1,[Use password quality checks])]
	)
])

dnl ---------------------------------------------------------------------------
dnl - Check for Python 3
dnl - Check for platform Python interpreter
dnl ---------------------------------------------------------------------------

AS_IF([test "x${PYTHON}" != "x"], [
    AC_MSG_NOTICE([Python user override detected, ${PYTHON}])
])

AC_MSG_NOTICE([Checking for platform Python])
AC_PATH_PROG(PLATFORM_PYTHON, platform-python, [], [/usr/libexec$PATH_SEPARATOR$PATH])

dnl Only use platform-python when there is no override
if test \( "x${PLATFORM_PYTHON}" != "x" -a "x${PYTHON}" = "x" \); then
    dnl platform-python executable detected (it's always Python 3)
    AC_MSG_NOTICE([Using platform Python as default Python 3 interpreter])
    PYTHON=${PLATFORM_PYTHON}
fi

AM_PATH_PYTHON(3.6)


dnl ---------------------------------------------------------------------------
dnl - Check for cmocka unit test framework http://cmocka.cryptomilk.org/
dnl ---------------------------------------------------------------------------
PKG_CHECK_EXISTS(cmocka,
    [AC_CHECK_HEADERS([stdarg.h stddef.h setjmp.h],
        [], dnl We are only intrested in action-if-not-found
        [AC_MSG_WARN([Header files stdarg.h stddef.h setjmp.h are required by cmocka])
         cmocka_required_headers="no"
        ]
    )
    AS_IF([test x"$cmocka_required_headers" != x"no"],
          [PKG_CHECK_MODULES([CMOCKA], [cmocka], [have_cmocka="yes"])]
    )],
    dnl PKG_CHECK_EXISTS ACTION-IF-NOT-FOUND
    [AC_MSG_WARN([No libcmocka library found, cmocka tests will not be built])]
)
AM_CONDITIONAL([HAVE_CMOCKA], [test x$have_cmocka = xyes])

dnl ---------------------------------------------------------------------------
dnl - Check for POPT
dnl ---------------------------------------------------------------------------
POPT_LIBS=
PKG_CHECK_MODULES([POPT], [popt], [],
    [AC_CHECK_HEADER([popt.h], [], [AC_MSG_ERROR([popt.h not found])])
     AC_CHECK_LIB([popt], [poptGetContext], [POPT_LIBS="-lpopt"])
     AC_SUBST(POPT_LIBS)
    ]
)

dnl ---------------------------------------------------------------------------
dnl - Check for SASL
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([SASL], [libsasl2])

dnl ---------------------------------------------------------------------------
dnl - Check for XMLRPC-C
dnl ---------------------------------------------------------------------------
AS_IF([test x"$with_ipa_join_xml" = xyes], [
    PKG_CHECK_MODULES([XMLRPC], [xmlrpc xmlrpc_client xmlrpc_util])
])

dnl ---------------------------------------------------------------------------
dnl - Check for jansson and libcurl for ipa-join
dnl ---------------------------------------------------------------------------
AS_IF([test x"$with_ipa_join_xml" = xno], [
    PKG_CHECK_MODULES([JANSSON], [jansson])
    PKG_CHECK_MODULES([LIBCURL], [libcurl])
])

dnl ---------------------------------------------------------------------------
dnl - Check for libintl
dnl ---------------------------------------------------------------------------
SAVE_LIBS="$LIBS"
LIBINTL_LIBS=
AC_CHECK_HEADER(libintl.h, [], [AC_MSG_ERROR([libintl.h not found, please install xgettext])])
AC_SEARCH_LIBS([bindtextdomain], [libintl],[], [])
if test "x$ac_cv_search_bindtextdomain" = "xno" ; then
  AC_MSG_ERROR([libintl is not found and your libc does not support gettext, please install xgettext])
elif test "x$ac_cv_search_bindtextdomain" != "xnone required" ; then
  LIBINTL_LIBS="$ac_cv_search_bindtextdomain"
fi
LIBS="$SAVELIBS"
AC_SUBST(LIBINTL_LIBS)

dnl ---------------------------------------------------------------------------
dnl - Check for libini_config
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([INI], [ini_config >= 1.2.0])

dnl ---------------------------------------------------------------------------
dnl - Get /etc/sysconfig directory path
dnl ---------------------------------------------------------------------------
AC_ARG_WITH([sysconfenvdir],
            AS_HELP_STRING([--with-sysconfenvdir=DIR],
			   [Directory for daemon environment files]),
            [sysconfenvdir=$with_sysconfenvdir],
            [sysconfenvdir="${sysconfdir}/sysconfig"])
AC_SUBST([sysconfenvdir])

dnl ---------------------------------------------------------------------------
dnl - Get /run directory path
dnl - available in autoconf 2.70+
dnl ---------------------------------------------------------------------------
AC_ARG_WITH([runstatedir],
            AS_HELP_STRING([--with-runstatedir=DIR],
                           [Runtime data directory]),
            [runstatedir=$with_runstatedir],
            [runstatedir="/run"])
AC_SUBST([runstatedir])

dnl ---------------------------------------------------------------------------
dnl - Check for systemd directories
dnl ---------------------------------------------------------------------------

PKG_CHECK_EXISTS([systemd], [], [AC_MSG_ERROR([systemd not found])])
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
               [Directory for systemd service files]),
            [systemdsystemunitdir=$with_systemdsystemunitdir],
        [systemdsystemunitdir=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir])

AC_ARG_WITH([systemdtmpfilesdir],
            AS_HELP_STRING([--with-systemdtmpfilesdir=DIR],
               [Directory for systemd-tmpfiles configuration files]),
            [systemdtmpfilesdir=$with_systemdtmpfilesdir],
        [systemdtmpfilesdir=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=tmpfilesdir systemd)])
AC_SUBST([systemdtmpfilesdir])

AC_ARG_WITH([systemdcatalogdir],
            AS_HELP_STRING([--with-systemdcatalogdir=DIR],
               [Directory for systemd journal catalog files]),
            [systemdcatalogdir=$with_systemdcatalogdir],
        [systemdcatalogdir=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=catalogdir systemd)])
AC_SUBST([systemdcatalogdir])

dnl ---------------------------------------------------------------------------
dnl - Server-only configuration
dnl ---------------------------------------------------------------------------

AM_COND_IF([ENABLE_SERVER], [
    m4_include(server.m4)
])
AM_CONDITIONAL([USE_SSS_NSS_TIMEOUT], [test "x$ac_cv_have_decl_sss_nss_getpwnam_timeout" = xyes])

dnl ---------------------------------------------------------------------------
dnl - Check if IPA certauth plugin can be build
dnl ---------------------------------------------------------------------------

AM_CONDITIONAL([BUILD_IPA_CERTAUTH_PLUGIN],
               [test x$have_certauth_plugin = xyes -a x"$SSSCERTMAP_LIBS" != x])
AM_COND_IF([BUILD_IPA_CERTAUTH_PLUGIN], [
    AC_DEFINE([HAVE_KRB5_CERTAUTH_PLUGIN], [1],
        [MIT Kerberos version supports certauth plugin])
    AM_COND_IF([ENABLE_SERVER],
               [AC_MSG_NOTICE([Build IPA KDB certauth plugin])],
               [AC_MSG_WARN([Cannot build IPA KDB certauth plugin])])
])

AM_CONDITIONAL([BUILD_IPA_KDCPOLICY_PLUGIN],
               [test x$have_kdcpolicy_plugin = xyes])

AM_CONDITIONAL([BUILD_IPA_ISSUE_PAC],
               [test x$have_kdb_issue_pac = xyes])

dnl ---------------------------------------------------------------------------
dnl - Check for program paths
dnl ---------------------------------------------------------------------------
AC_PATH_PROG(UNLINK, unlink, [AC_MSG_ERROR([unlink not found])])

dnl ---------------------------------------------------------------------------
dnl - Set the data install directory since we don't use pkgdatadir
dnl ---------------------------------------------------------------------------

IPA_DATA_DIR="$datadir/ipa"
IPA_SYSCONF_DIR="$sysconfdir/ipa"
AC_SUBST(IPA_DATA_DIR)
AC_SUBST(IPA_SYSCONF_DIR)

dnl ---------------------------------------------------------------------------
dnl Translations
dnl ---------------------------------------------------------------------------
# POTFILES.in needs to be created before calling AM_GNU_GETTEXT
AC_CONFIG_COMMANDS([po/POTFILES.in],
		   [find_start_pwd=`pwd` && dnl
		    cd "${ac_abs_top_srcdir}" && dnl strip prefixes from find
		    find . dnl
			-path "./rpmbuild" -prune -o dnl
			-path "./${PACKAGE}-*" -prune -o dnl dist directories
			-path '*/build' -prune -o dnl Python builds
			-path '*/dist' -prune -o dnl Python dists
			-path './.tox' -prune -o dnl Python tox test
			-path './conf*' -prune -o dnl generated by configure
			-name '*.py' -print -o dnl
			-name '*.c' -print -o dnl
			-name '*.h' -print dnl
			> po/POTFILES.in && dnl
			cd "${find_start_pwd}"])
AC_SUBST(GETTEXT_DOMAIN, [ipa])
AM_GNU_GETTEXT_VERSION([0.18.2])
AM_GNU_GETTEXT([external])

dnl integrate our custom hacks into gettextize infrastructure
AC_CONFIG_COMMANDS([po/Makefile-hackit],
		   [echo "include Makefile.hack" dnl
		    >> "${ac_abs_top_srcdir}/po/Makefile"])

AC_PROG_MKDIR_P
AC_PROG_AWK
AC_PROG_SED

AC_PATH_PROG(MSGATTRIB, msgattrib, [no])
if test "x$MSGATTRIB" = "xno"; then
    AC_MSG_ERROR([msgattrib not found, install gettext])
fi
AC_SUBST([MSGATTRIB])

dnl ---------------------------------------------------------------------------
dnl IPA platform
dnl ---------------------------------------------------------------------------
AC_ARG_WITH([ipaplatform],
	    [AC_HELP_STRING([--with-ipaplatform],
			    [IPA platform module to use])],
	    [IPAPLATFORM=${withval}],
	    [IPAPLATFORM=""])
AC_MSG_CHECKING([supported IPA platform])

if test "x${IPAPLATFORM}" != "x"; then
	if test ! -d "${srcdir}/ipaplatform/${IPAPLATFORM}"; then
		AC_MSG_ERROR([IPA platform ${IPAPLATFORM} is not supported])
	fi
else
	dnl auto-detect, read ID and ID_LIKE from /etc/os-release
	if test -r "/etc/os-release"; then
		platform_ids=$(source /etc/os-release; echo "$ID $ID_LIKE")
	else
		AC_MSG_ERROR([unable to read /etc/os-release])
	fi
	if test "x${platform_ids}" == "x"; then
		AC_MSG_ERROR([unable to find ID variable in /etc/os-release])
	fi

	dnl find first available platform from ID and ID_LIKE
	for platform in ${platform_ids}; do
		if test -d "${srcdir}/ipaplatform/${platform}"; then
			IPAPLATFORM=${platform}
			break
		fi
	done

	dnl Did we find a supported platform?
	if test "x${IPAPLATFORM}" == "x"; then
		AC_MSG_ERROR([IPA platforms ${platform_ids} are not supported])
	fi
fi

AC_SUBST([IPAPLATFORM])
AC_MSG_RESULT([${IPAPLATFORM}])

if test "x${IPAPLATFORM}" == "xdebian"; then
    HTTPD_GROUP="www-data"
    KRB5KDC_SERVICE="krb5-kdc.service"
    NAMED_GROUP="bind"
    ODS_USER="opendnssec"
    ODS_GROUP="opendnssec"
    # see https://www.debian.org/doc/packaging-manuals/python-policy/ap-packaging_tools.html
    PYTHON_INSTALL_EXTRA_OPTIONS="--install-layout=deb"
else
    HTTPD_GROUP="apache"
    KRB5KDC_SERVICE="krb5kdc.service"
    NAMED_GROUP="named"
    ODS_USER="ods"
    ODS_GROUP="ods"
    PYTHON_INSTALL_EXTRA_OPTIONS=""
fi

AC_MSG_CHECKING([HTTPD_GROUP])
AC_SUBST([HTTPD_GROUP])
AC_MSG_RESULT([${HTTPD_GROUP}])

AC_SUBST([KRB5KDC_SERVICE])

AC_MSG_CHECKING([NAMED_GROUP])
AC_SUBST([NAMED_GROUP])
AC_MSG_RESULT([${NAMED_GROUP}])

AC_MSG_CHECKING([ODS_USER])
AC_SUBST([ODS_USER])
AC_MSG_RESULT([${ODS_USER}])

AC_MSG_CHECKING([ODS_GROUP])
AC_SUBST([ODS_GROUP])
AC_MSG_RESULT([${ODS_GROUP}])

AC_MSG_CHECKING([python setup.py install extra options])
AC_SUBST([PYTHON_INSTALL_EXTRA_OPTIONS])
if test "x${PYTHON_INSTALL_EXTRA_OPTIONS}" == "x"; then
    AC_MSG_RESULT([none])
else
    AC_MSG_RESULT([${PYTHON_INSTALL_EXTRA_OPTIONS}])
fi

dnl ---------------------------------------------------------------------------
dnl Version information from VERSION.m4 and command line
dnl ---------------------------------------------------------------------------
dnl Are we in source tree?
AM_CONDITIONAL([IS_GIT_SNAPSHOT], [test "IPA_VERSION_IS_GIT_SNAPSHOT" == "yes"])
AM_COND_IF([IS_GIT_SNAPSHOT], [
	AC_MSG_CHECKING([if source directory is a Git reposistory])
	if test ! -e "${srcdir}/.git"; then
		AC_MSG_ERROR([Git reposistory is required by VERSION.m4 IPA_VERSION_IS_GIT_SNAPSHOT but not found])
	else
		AC_MSG_RESULT([yes])
	fi
])

AC_ARG_WITH([vendor-suffix],
            AS_HELP_STRING([--with-vendor-suffix=STRING],
			   [Vendor string used by package system, e.g. "-1.fc24"]),
            [VENDOR_SUFFIX=${withval}],
	    [VENDOR_SUFFIX=""])

AC_SUBST([API_VERSION], [IPA_API_VERSION])
AC_SUBST([DATA_VERSION], [IPA_DATA_VERSION])
AC_SUBST([NUM_VERSION], [IPA_NUM_VERSION])
AC_SUBST(VENDOR_SUFFIX)
AC_SUBST([VERSION], [IPA_VERSION])
AC_SUBST([GIT_VERSION], [IPA_GIT_VERSION])
AC_SUBST([GIT_BRANCH], [IPA_GIT_BRANCH])
AC_SUBST([KRB5_BUILD_VERSION], [IPA_KRB5_BUILD_VERSION])
# used by Makefile.am for files depending on templates
AC_SUBST([CONFIG_STATUS])

# workaround for syntax clash between make and automake
AC_SUBST([MK_IFEQ], [ifeq])
AC_SUBST([MK_ELSE], [else])
AC_SUBST([MK_ENDIF], [endif])
AC_SUBST([MK_ASSIGN], [=])

dnl ---------------------------------------------------------------------------
dnl - Check for SELinux policy devel
dnl ---------------------------------------------------------------------------

AC_ARG_ENABLE([selinux],
    [AC_HELP_STRING([--enable-selinux], [Disable SELinux support])],
    [case "${enableval}" in
         yes) enable_selinux=yes ;;
          no) enable_selinux=no ;;
           *) AC_MSG_ERROR([bad value ${enableval} for --enable-selinux]) ;;
     esac],
    [enable_selinux=])

if test "x$enable_selinux" = "x" ; then
        selinux_makefile=/usr/share/selinux/devel/Makefile
        AC_SUBST([selinux_makefile])

        AS_IF([test -f "$selinux_makefile"],
              [enable_selinux=yes],
              [enable_selinux=no])
fi

AM_CONDITIONAL([BUILD_SELINUX_POLICY], [test "x$enable_selinux" = xyes])

dnl ---------------------------------------------------------------------------
dnl Finish
dnl ---------------------------------------------------------------------------

# Turn on the additional warnings last, so -Werror doesn't affect other tests.

AC_ARG_ENABLE(more-warnings,
	[AC_HELP_STRING([--enable-more-warnings],
	[Maximum compiler warnings])],
	set_more_warnings="$enableval",[
        	if test -d $srcdir/.git; then
        		set_more_warnings=yes
              	else
                  	set_more_warnings=no
              	fi
        ])
AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
        AC_MSG_RESULT(yes)
        CFLAGS="\
        -Wall \
        -Wchar-subscripts -Wmissing-declarations -Wmissing-prototypes \
        -Wnested-externs -Wpointer-arith \
        -Wcast-align -Wsign-compare \
        -Wshadow -Wstrict-prototypes \
        $CFLAGS"
else
        AC_MSG_RESULT(no)
fi

AM_CONDITIONAL([VERBOSE_MAKE], [test "x${AM_DEFAULT_VERBOSITY}" == "x1"])

dnl ---------------------------------------------------------------------------
dnl Linters
dnl ---------------------------------------------------------------------------
AC_ARG_ENABLE([i18ntests],
	       AC_HELP_STRING([--disable-i18ntests],
			      [do not execute ipatests/i18n.py
			       (depends on python-polib)]),
		,
		[enable_i18ntests="yes"]
)
AC_SUBST([i18ntests])
AM_CONDITIONAL([WITH_POLINT], [test "x${enable_i18ntests}" == "xyes"])

AC_ARG_ENABLE([pylint],
	    AS_HELP_STRING([--enable-pylint],
			   [Require pylint. Default is autodetection with
			    "python -m pylint".]),
	    [PYLINT=$enableval],
	    [PYLINT=check]
)

if test x$PYLINT != xno; then
    AC_MSG_CHECKING([for Pylint])
    $PYTHON -m pylint --version >/dev/null 2>&1
    if test "$?" != "0"; then
        if test x$PYLINT = xcheck; then
            PYLINT=no
            AC_MSG_NOTICE([cannot find optional pylint for $PYTHON])
        else
            AC_MSG_ERROR([cannot find pylint for $PYTHON])
        fi
    else
        PYLINT=yes
        AC_MSG_RESULT([yes])
    fi
fi
AC_SUBST([PYLINT])
AM_CONDITIONAL([WITH_PYLINT], [test "x${PYLINT}" != "xno"])


AC_ARG_WITH([jslint],
        AS_HELP_STRING([--with-jslint=[FILE]],
                       [path to JavaScript linter. Default is autodetection of
                       utility "jsl" ]),
        [JSLINT="$withval"],
        [JSLINT=check]
)

AS_CASE([$JSLINT],
    [yes], [AC_PATH_PROG([JSLINT], [jsl], [missing])
            if test $JSLINT = missing; then
                AC_MSG_FAILURE([jsl is missing])
            fi],
    [no], [],
    [check], [AC_PATH_PROG([JSLINT], [jsl], [no])],
    dnl user setting
    [if ! test -f "$JSLINT"; then
        AC_MSG_RESULT([$JSLINT non-existing])
        AC_MSG_FAILURE([invalid value $JSLINT for jsl])
     fi
     if ! test -x "$JSLINT"; then
        AC_MSG_RESULT([$JSLINT non-executable])
        AC_MSG_FAILURE([invalid value $JSLINT for jsl])
     fi]
)
AC_SUBST([JSLINT])
AM_CONDITIONAL([WITH_JSLINT], [test "x${JSLINT}" != "xno"])


AC_ARG_ENABLE(
    [rpmlint],
    [AC_HELP_STRING([--enable-rpmlint], [Enable rpmlint for the rpm spec])],
    [case "${enableval}" in
         yes) ENABLE_RPMLINT=yes ;;
          no) ENABLE_RPMLINT=no ;;
           *) AC_MSG_ERROR([bad value ${enableval} for --enable-rpmlint]) ;;
     esac],
    [ENABLE_RPMLINT=no])
AS_IF([test "x$ENABLE_RPMLINT" = "xyes"],
      [AC_PATH_PROG([RPMLINT], [rpmlint])
       AS_IF([test "x$RPMLINT" = "x"],
             [AC_MSG_ERROR([Could not find rpmlint])])],
)
AM_CONDITIONAL([WITH_RPMLINT], [test "x$ENABLE_RPMLINT" = "xyes"])

AM_CONDITIONAL([HAVE_UNSHARE],
    [test "x${ac_cv_func_unshare}" = "xyes" -a "x${ac_cv_func_chroot}" = "xyes"])

# Flags

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)


# Files
AC_CONFIG_FILES([
    Makefile
    asn1/Makefile
    asn1/asn1c/Makefile
    client/Makefile
    client/share/Makefile
    client/man/Makefile
    client/sysconfig/Makefile
    client/systemd/Makefile
    contrib/completion/Makefile
    contrib/Makefile
    daemons/dnssec/Makefile
    daemons/Makefile
    daemons/ipa-kdb/Makefile
    daemons/ipa-sam/Makefile
    daemons/ipa-otpd/Makefile
    daemons/ipa-slapi-plugins/Makefile
    daemons/ipa-slapi-plugins/libotp/Makefile
    daemons/ipa-slapi-plugins/ipa-cldap/Makefile
    daemons/ipa-slapi-plugins/ipa-dns/Makefile
    daemons/ipa-slapi-plugins/ipa-enrollment/Makefile
    daemons/ipa-slapi-plugins/ipa-graceperiod/Makefile
    daemons/ipa-slapi-plugins/ipa-lockout/Makefile
    daemons/ipa-slapi-plugins/ipa-otp-counter/Makefile
    daemons/ipa-slapi-plugins/ipa-otp-lasttoken/Makefile
    daemons/ipa-slapi-plugins/ipa-pwd-extop/Makefile
    daemons/ipa-slapi-plugins/ipa-extdom-extop/Makefile
    daemons/ipa-slapi-plugins/ipa-winsync/Makefile
    daemons/ipa-slapi-plugins/ipa-version/Makefile
    daemons/ipa-slapi-plugins/ipa-uuid/Makefile
    daemons/ipa-slapi-plugins/ipa-modrdn/Makefile
    daemons/ipa-slapi-plugins/ipa-sidgen/Makefile
    daemons/ipa-slapi-plugins/ipa-range-check/Makefile
    daemons/ipa-slapi-plugins/topology/Makefile
    init/systemd/Makefile
    init/tmpfilesd/Makefile
    init/Makefile
    install/Makefile
    install/certmonger/Makefile
    install/custodia/Makefile
    install/html/Makefile
    install/migration/Makefile
    install/share/Makefile
    install/share/advise/Makefile
    install/share/advise/legacy/Makefile
    install/share/profiles/Makefile
    install/share/schema.d/Makefile
    install/ui/Makefile
    install/ui/css/Makefile
    install/ui/src/Makefile
    install/ui/src/libs/Makefile
    install/ui/images/Makefile
    install/ui/build/Makefile
    install/ui/build/dojo/Makefile
    install/ui/build/freeipa/Makefile
    install/tools/Makefile
    install/tools/man/Makefile
    install/updates/Makefile
    install/restart_scripts/Makefile
    install/wsgi/Makefile
    install/oddjob/Makefile
    ipaclient/Makefile
    ipalib/Makefile
    ipaplatform/Makefile
    ipapython/Makefile
    ipasphinx/Makefile
    ipaserver/Makefile
    ipatests/Makefile
    ipatests/man/Makefile
    pypi/Makefile
    pypi/freeipa/Makefile
    pypi/ipa/Makefile
    pypi/ipaserver/Makefile
    pypi/ipatests/Makefile
    po/Makefile.in
    po/Makefile.hack
    selinux/Makefile
    selinux/nfast/Makefile
    selinux/luna/Makefile
    util/Makefile
])

AC_OUTPUT

echo "
                    IPA Server $VERSION
                    ========================

        vendor version:           ${VERSION}${VENDOR_SUFFIX}
        ipaplatform:              ipaplatform.${IPAPLATFORM}
        prefix:                   ${prefix}
        exec_prefix:              ${exec_prefix}
        libdir:                   ${libdir}
        bindir:                   ${bindir}
        sbindir:                  ${sbindir}
        sysconfdir:               ${sysconfdir}
        sysconfenvdir:            ${sysconfenvdir}
        localstatedir:            ${localstatedir}
        datadir:                  ${datadir}
        source code location:     ${srcdir}
        compiler:                 ${CC}
        cflags:                   ${CFLAGS}
        Python:                   ${PYTHON} (${PYTHON_VERSION})
        pylint:                   ${PYLINT}
        jslint:                   ${JSLINT}
        rpmlint:                  ${ENABLE_RPMLINT}
        LDAP libs:                ${LDAP_LIBS}
        OpenSSL crypto libs:      ${CRYPTO_LIBS}
        KRB5 libs:                ${KRB5_LIBS}
        systemdsystemunitdir:     ${systemdsystemunitdir}"

AM_COND_IF([ENABLE_SERVER], [
    echo "\
        pwquality libs:           ${PWQUALITY_LIBS}
        KRAD libs:                ${KRAD_LIBS}
        krb5rundir:               ${krb5rundir}
        systemdtmpfilesdir:       ${systemdtmpfilesdir}
        build mode:               server & client"
], [
    echo "\
        build mode:               client only"
])
AM_COND_IF([WITH_IPATESTS], [
    echo "\
        with ipatests:            yes"
], [
    echo "\
        with ipatests:            no"
])
AM_COND_IF([WITH_IPA_JOIN_XML], [
    echo "\
        ipa-join RPC mode:        XML-RPC"
], [
    echo "\
        ipa-join RPC mode:        JSON-RPC"
])
AM_COND_IF([BUILD_SELINUX_POLICY], [
    echo "\
        build SELinux policy:     yes"
], [
    echo "\
        build SELinux policy:     no"
])

