########################################################
# FreeIPA Version                                      #
#                                                      #
# FreeIPA versions are as follows                      #
# 1.0.x                  New production series         #
# 1.0.x{alpha,beta,rc}y  Alpha/Preview/Testing, Beta,  #
#                           Release Candidate          #
# 1.0.0.dev20170102030405+gitabcdefg  Build from GIT   #
#                                                      #
########################################################

########################################################
# This are the main version numbers                    #
#                                                      #
# <MAJOR>.<MINOR>.<RELEASE>                            #
#                                                      #
# e.g. define(IPA_VERSION_MAJOR, 1)                    #
#      define(IPA_VERSION_MINOR, 0)                    #
#      define(IPA_VERSION_RELEASE, 0)                  #
#  ->  "1.0.0"                                         #
########################################################
define(IPA_VERSION_MAJOR, 4)
define(IPA_VERSION_MINOR, 13)
define(IPA_VERSION_RELEASE, 0)

########################################################
# For 'pre' releases the version will be               #
#                                                      #
# <MAJOR>.<MINOR>.<RELEASE><PRE_RELEASE>               #
#                                                      #
# pre releases start with RELEASE 90. After pre1 has   #
# been released, RELEASE is bumpled to 91, and so on   #
#                                                      #
# e.g. define(IPA_VERSION_PRE_RELEASE, rc1)            #
#  ->  "1.0.0rc1"                                      #
########################################################
define(IPA_VERSION_PRE_RELEASE, )

########################################################
# To mark GIT snapshots this should be set to 'yes'    #
# in the development BRANCH, and set to 'no' only in   #
# the IPA_X_X_RELEASE BRANCH                           #
#                                                      #
# <MAJOR>.<MINOR>.<RELEASE>.dev<TIMESTAMP>+git<hash>   #
#                                                      #
# e.g. define(IPA_VERSION_IS_GIT_SNAPSHOT, yes)        #
#  ->  "1.0.0.dev20170102030405+gitabcdefg"            #
#                                                      #
# This option works only with GNU m4:                  #
# it requires esyscmd m4 macro.                        #
########################################################
define(IPA_VERSION_IS_GIT_SNAPSHOT, yes)

########################################################
# git development branch:                              #
#                                                      #
# - master: define(IPA_GIT_BRANCH, master)             #
# - ipa-X-X: define(IPA_GIT_BRANCH,                    #
#       ipa-IPA_VERSION_MAJOR-IPA_VERSION_MINOR)       #
########################################################
define(IPA_GIT_BRANCH, master)
dnl define(IPA_GIT_BRANCH, ipa-IPA_VERSION_MAJOR-IPA_VERSION_MINOR)

########################################################
# The version of IPA data. This is used to identify    #
# incompatibilities in data that could cause issues    #
# with replication. If the built-in versions don't     #
# match exactly then replication will fail.            #
#                                                      #
# The format is %Y%m%d%H%M%S                           #
#                                                      #
# e.g. define(IPA_DATA_VERSION, 20100614120000)        #
#  ->  "20100614120000"                                #
########################################################
define(IPA_DATA_VERSION, 20100614120000)

########################################################
# The version of the IPA API. This controls which      #
# client versions can use the XML-RPC and json APIs    #
#                                                      #
# A change to existing API requires a MAJOR version    #
# update.  The addition of new API bumps the MINOR     #
# version.                                             #
#                                                      #
# The format is a whole number                         #
#                                                      #
########################################################
define(IPA_API_VERSION_MAJOR, 2)
# Last change: add cert_approve command
define(IPA_API_VERSION_MINOR, 255)

########################################################
# Following values are auto-generated from values above
# That way m4 madness lies
########################################################

########################################################
# IPA_NUM_VERSION is auto-generated
# format suitable for aritmetical comparison.
########################################################
dnl for some reason AC_SUBST([NUM_VERSION], [IPA_NUM_VERSION])
dnl does not work when we use macro "format" instead of "esyscmd"
define(IPA_NUM_VERSION, esyscmd(printf "%d%02d%02d" IPA_VERSION_MAJOR IPA_VERSION_MINOR IPA_VERSION_RELEASE))


########################################################
# IPA_API_VERSION: format is APImajor.APIminor
########################################################
define(IPA_API_VERSION, IPA_API_VERSION_MAJOR.IPA_API_VERSION_MINOR)


########################################################
# IPA_VERSION is one string formated according to rules
# described on top of this file
########################################################
dnl helper for translit in IPA_VERSION
define(NEWLINE,`
')

dnl Git snapshot: dev20170102030405+gitabcdefg
define(IPA_GIT_VERSION, translit(dnl remove new lines from version (from esyscmd)
ifelse(IPA_VERSION_IS_GIT_SNAPSHOT, yes,dnl
dev
esyscmd(date -u +'%Y%m%d%H%M')dnl 20170102030405
+git
esyscmd(git log -1 --format="%h" HEAD),dnl abcdefg
), NEWLINE))
dnl IPA_GIT_VERSION end

define(IPA_VERSION, translit(dnl remove new lines from version (from esyscmd)
dnl 1.0.0
IPA_VERSION_MAJOR.IPA_VERSION_MINOR.IPA_VERSION_RELEASE
IPA_VERSION_PRE_RELEASE
dnl version with Git snapshot: 1.0.0.dev20170102030405+gitabcdefg
ifelse(IPA_VERSION_IS_GIT_SNAPSHOT, yes,
.
IPA_GIT_VERSION),
NEWLINE)) dnl IPA_VERSION end

########################################################
# Version of MIT krb5 used to build IPA
########################################################
define(IPA_KRB5_BUILD_VERSION, translit(esyscmd(krb5-config --version | awk '{ print $NF }'), NEWLINE))

dnl DEBUG: uncomment following lines and run command m4 VERSION.m4
dnl `IPA_VERSION: ''IPA_VERSION'
dnl `IPA_GIT_VERSION: ''IPA_GIT_VERSION'
dnl `IPA_GIT_BRANCH: ''IPA_GIT_BRANCH'
dnl `IPA_API_VERSION: ''IPA_API_VERSION'
dnl `IPA_DATA_VERSION: ''IPA_DATA_VERSION'
dnl `IPA_NUM_VERSION: ''IPA_NUM_VERSION'
dnl `IPA_KRB5_BUILD_VERSION: ''IPA_KRB5_BUILD_VERSION'
