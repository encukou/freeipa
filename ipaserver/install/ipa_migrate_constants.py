# ipa-migrate constants
#
# Lists of all the plugins and settings
#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license

# Generic constants
BIND_DN = "cn=directory manager"
LOG_FILE_NAME = "/var/log/ipa-migrate.log"
LDIF_FILE_NAME = "/var/log/ipa-migrate.ldif"
CONFLICT_FILE_NAME = "/var/log/ipa-migrate-conflict.ldif"

# Operational attributes to strip from the remote server
STRIP_OP_ATTRS = [
    'modifiersname',
    'modifytimestamp',
    'creatorsname',
    'createtimestamp',
    'nsuniqueid',
    'dsentrydn',
    'entryuuid',
    'entrydn',
    'entryid',
    'entryusn',
    'numsubordinates',
    'parentid',
    'tombstonenumsubordinates'
]

# Operational attributes that we would want to remove from the local entry if
# they don't exist in the remote entry
POLICY_OP_ATTRS = [
    'nsaccountlock',
    'passwordexpiratontime',
    'passwordgraceusertime',
    'pwdpolicysubentry',
    'passwordexpwarned',
    'passwordretrycount',
    'retrycountresettime',
    'accountunlocktime',
    'passwordhistory',
    'passwordallowchangetime',
    'pwdreset'
]

# Atributes to strip from users/groups
STRIP_ATTRS = [
    'krbextradata',
    'krblastfailedauth',
    'krblastpwdchange',
    'krbloginfailedcount',
    'krbticketflags',
    'krbmkey',
    'ipasshpubkey',  # We keep this for users (handled in clean_entry())
    'mepmanagedentry',  # It will be rebuilt on new server
    'memberof',
    # from ds-migrate....
    'krbprincipalkey', 'memberofindirect', 'memberindirect',  # User
    'memberofindirect', 'memberindirect',  # Groups
]

# Attributes to ignore during entry comparison, but these attributes will be
# applied when creating a new entry
IGNORE_ATTRS = [
    'description',
    'ipasshpubkey',
    'ipantsecurityidentifier',  # Need this in production mode
    'ipantflatname',
    'ipamigrationenabled',
    'ipauniqueid',
    'serverhostname',
    'krbpasswordexpiration',
    'krblastadminunlock',
    'krbpwdpolicyreference',  # COS attribute
]

# For production mode, bring everything over
PROD_ATTRS = [
    'ipantsecurityidentifier',
    'ipanthash',
    'ipantlogonscript',
    'ipantprofilepath',
    'ipanthomedirectory',
    'ipanthomedirectorydrive'
]

AD_USER_ATTRS = [  # ipaNTUserAttrs objectclass
    'ipantsecurityidentifier',  # required
    'ipanthash',
    'ipantlogonscript',
    'ipantprofilepath',
    'ipanthomedirectory',
    'ipanthomedirectorydrive'
]

AD_DOMAIN_ATTRS = [  # ipaNTDomainAttrs objectclass
    'ipantsecurityidentifier',  # required
    'ipantflatName',  # required
    'ipantdomainguid',  # required
    'ipantfallbackprimarygroup',
]

AD_TRUST_ATTRS = [  # ipaNTTrustedDomain objectclass
    'ipanttrusttype',
    'ipanttrustattributes',
    'ipanttrustdirection',
    'ipanttrustpartner',
    'ipantflatname',
    'ipanttrustauthoutgoing',
    'ipanttrustauthincoming',
    'ipanttrusteddomainsid',
    'ipanttrustforesttrustInfo',
    'ipanttrustposixoffset',
    'ipantsupportedencryptiontypes',
    'ipantsidblacklistincoming',
    'ipantsidblacklistoutgoing',
    'ipantadditionalsuffixes',
]

DNA_REGEN_VAL = "-1"

DNA_REGEN_ATTRS = [
    'uidnumber',
    'gidnumber',
    'ipasubuidnumber',
    'ipasubgidnumber',
]

STRIP_OC = [
    'meporiginentry',
]

#
# The DS_CONFIG mapping breaks each config entry (or type of entry) into its
# own catagory. Each catagory, or type, as DN list "dn", the attributes# we
# are intrested in.  These attributes are broken into single valued "attrs",
# or multi-valued attributes "multivalued".  If the attributes is single
# valued then the value is replaced, if it's multivalued then it is "appended"
#
# The "label" and "count" attributes are used for the Summary Report
#
DS_CONFIG = {
    'config': {
        'dn': ['cn=config'],
        'attrs': [
            # Should this be a tuple with possible conditions?
            # Higher value wins?
            'nsslapd-idletimeout',
            'nsslapd-ioblocktimeout',
            'nsslapd-sizelimit',
            'nsslapd-timelimit',
            'nsslapd-ndn-cache-max-size',
            'nsslapd-maxsasliosize',
            'nsslapd-maxthreadsperconn',
            'nsslapd-listen-backlog-size',
            'nsslapd-ignore-time-skew',
            'nsslapd-disk-monitoring',
            'nsslapd-anonlimitsdn',
            'nsslapd-auditlog-display-attrs',
            'nsslapd-allowed-sasl-mechanisms',
            'nsslapd-enable-upgrade-hash',
            'nsslapd-localssf',
            'nsslapd-minssf',
            'nsslapd-minssf-exclude-rootdse',
            'nsslapd-max-filter-nest-level',
            'nsslapd-ssl-check-hostname',
            'nsslapd-validate-cert',
            'nsslapd-unhashed-pw-switch',
            'nsslapd-maxbersize'
            # access log rotation
            'nsslapd-accesslog-logexpirationtime',
            'nsslapd-accesslog-logexpirationtimeunit',
            'nsslapd-accesslog-logmaxdiskspace',
            'nsslapd-accesslog-logminfreediskspace',
            'nsslapd-accesslog-logrotationsync-enabled',
            'nsslapd-accesslog-logrotationsynchour',
            'nsslapd-accesslog-logrotationsyncmin',
            'nsslapd-accesslog-logrotationtime',
            'nsslapd-accesslog-logrotationtimeunit',
            'nsslapd-accesslog-maxlogsize',
            'nsslapd-accesslog-maxlogsperdir',
            # audit log rotation
            'nsslapd-auditlog-logexpirationtime',
            'nsslapd-auditlog-logexpirationtimeunit',
            'nsslapd-auditlog-logmaxdiskspace',
            'nsslapd-auditlog-logminfreediskspace',
            'nsslapd-auditlog-logrotationsync-enabled',
            'nsslapd-auditlog-logrotationsynchour',
            'nsslapd-auditlog-logrotationsyncmin',
            'nsslapd-auditlog-logrotationtime',
            'nsslapd-auditlog-logrotationtimeunit',
            'nsslapd-auditlog-maxlogsize',
            'nsslapd-auditlog-maxlogsperdir',
            # audit fail log rotation
            'nsslapd-auditfaillog-logexpirationtime',
            'nsslapd-auditfaillog-logexpirationtimeunit',
            'nsslapd-auditfaillog-logmaxdiskspace',
            'nsslapd-auditfaillog-logminfreediskspace',
            'nsslapd-auditfaillog-logrotationsync-enabled',
            'nsslapd-auditfaillog-logrotationsynchour',
            'nsslapd-auditfaillog-logrotationsyncmin',
            'nsslapd-auditfaillog-logrotationtime',
            'nsslapd-auditfaillog-logrotationtimeunit',
            'nsslapd-auditfaillog-maxlogsize',
            'nsslapd-seauditfaillogcuritylog-maxlogsperdir',
            # error log rotation
            'nsslapd-errorlog-logexpirationtime',
            'nsslapd-errorlog-logexpirationtimeunit',
            'nsslapd-errorlog-logmaxdiskspace',
            'nsslapd-errorlog-logminfreediskspace',
            'nsslapd-errorlog-logrotationsync-enabled',
            'nsslapd-errorlog-logrotationsynchour',
            'nsslapd-errorlog-logrotationsyncmin',
            'nsslapd-errorlog-logrotationtime',
            'nsslapd-errorlog-logrotationtimeunit',
            'nsslapd-errorlog-maxlogsize',
            'nsslapd-errorlog-maxlogsperdir',
            # security log rotation
            'nsslapd-securitylog-logexpirationtime',
            'nsslapd-securitylog-logexpirationtimeunit',
            'nsslapd-securitylog-logmaxdiskspace',
            'nsslapd-securitylog-logminfreediskspace',
            'nsslapd-securitylog-logrotationsync-enabled',
            'nsslapd-securitylog-logrotationsynchour',
            'nsslapd-securitylog-logrotationsyncmin',
            'nsslapd-securitylog-logrotationtime',
            'nsslapd-securitylog-logrotationtimeunit',
            'nsslapd-securitylog-maxlogsize',
            'nsslapd-securitylog-maxlogsperdir',
        ],
        'multivalued': [],
        'label': 'cn=config',
        'mode': 'all',
        'count': 0,
    },
    'ldbm_config': {
        'dn': ['cn=config,cn=ldbm database,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-lookthroughlimit',
            'nsslapd-idlistscanlimit',  # pick larger value?
            'nsslapd-import-cachesize',
            'nsslapd-search-bypass-filter-test',
            'nsslapd-search-use-vlv-index',
            'nsslapd-exclude-from-export',
            'nsslapd-pagedlookthroughlimit',
            'nsslapd-pagedidlistscanlimit',
            'nsslapd-rangelookthroughlimit',
            'nsslapd-backend-opt-level',
        ],
        'multivalued': [],
        'label': 'LDBM Config',
        'mode': 'all',
        'count': 0,
    },
    'ldbm_bdb': {
        'dn': ['cn=bdb,cn=config,cn=ldbm database,cn=plugins,cn=config'],
        'attrs': [
            # 'nsslapd-cache-autosize',
            # 'nsslapd-cache-autosize-split',
            # 'nsslapd-dbcachesize',
            'nsslapd-db-compactdb-interval',
            'nsslapd-db-compactdb-time',
            'nsslapd-db-locks',
            'nsslapd-import-cache-autosize',
            'nsslapd-import-cachesize',
            'nsslapd-db-deadlock-policy',
            'nsslapd-db-locks-monitoring-enabled',
            'nsslapd-db-locks-monitoring-threshold',
            'nsslapd-db-locks-monitoring-pause',
        ],
        'multivalued': [],
        'label': 'BDB Config',
        'mode': 'all',
        'count': 0,
    },
    'ldbm_mdb': {  # Future TODO
        'dn': ['cn=mdb,cn=config,cn=ldbm database,cn=plugins,cn=config'],
        'attrs': [],
        'multivalued': [],
        'label': 'MDB Config',
        'mode': 'all',
        'count': 0,
    },
    'backends': {  # cn=userroot,cn=ldbm database,cn=plugins,cn=config
        'dn': [
            'cn=changelog,cn=ldbm database,cn=plugins,cn=config',
            'cn=userRoot,cn=ldbm database,cn=plugins,cn=config',
        ],
        'attrs': [
            # 'nsslapd-cachesize',  # autotuned
            # 'nsslapd-cachememsize',  # autotuned
            # 'nsslapd-dncachememsize',

        ],
        'multivalued': [],
        'label': 'Userroot',
        'mode': 'all',
        'count': 0,
    },
    'referint': {
        'dn': ['cn=referential integrity postoperation,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-plugincontainerscope', 'nsslapd-pluginentryscope',
            'nsslapd-pluginexcludeentryscope', 'referint-update-delay'
        ],
        'multivalued': [
            'referint-membership-attr',
        ],
        'label': 'Referint Plugin',
        'mode': 'all',
        'count': 0,
    },
    'memberof': {
        'dn': ['cn=MemberOf Plugin,cn=plugins,cn=config'],
        'attrs': [],
        'multivalued': [
            'memberofgroupattr', 'memberofentryscope',
            'memberofentryscopeexcludesubtree',
        ],
        'label': 'MemberOf Plugin',
        'mode': 'all',
        'count': 0,
    },
    'ipa_winsync': {
        'dn': ['cn=ipa-winsync,cn=plugins,cn=config'],
        'attrs': [
            'ipawinsyncacctdisable', 'ipawinsyncdefaultgroupattr',
            'ipawinsyncdefaultgroupfilter', 'ipawinsyncforcesync',
            'ipawinsynchomedirattr', 'ipawinsyncloginshellattr',
            'ipawinsyncnewentryfilter', 'ipawinsyncnewuserocattr',
            'ipawinsyncrealmattr', 'ipawinsyncrealmfilter',
            'ipawinsyncuserflatten',
        ],
        'multivalued': [
            'ipaWinSyncUserAttr',
        ],
        'label': 'Winsync Plugin',
        'mode': 'all',
        'count': 0,
    },
    'topo_config': {
        'dn': ['cn=IPA Topology Configuration,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-topo-plugin-shared-binddngroup',
            'nsslapd-topo-plugin-shared-config-base'
            'nsslapd-topo-plugin-startup-delay',
        ],
        'multivalued': [
            'nsslapd-topo-plugin-shared-replica-root'
        ],
        'label': 'Topology Configuration',
        'mode': 'all',
        'count': 0,
    },
    'ipa_dns': {  # TODO - do admins ever turn this plugin off?
        'dn': ['cn=IPA DNS,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-pluginEnabled',
        ],
        'multivalued': [],
        'label': 'DNS Plugin',
        'mode': 'all',
        'count': 0,
    },
    'retro': {
        'dn': ['cn=Retro Changelog Plugin,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-changelogmaxage',
        ],
        'multivalued': [
            'nsslapd-include-suffix',
            'nsslapd-exclude-suffix',
            'nsslapd-exclude-attrs',
            'nsslapd-attribute',
        ],
        'label': 'Retro Changelog Plugin',
        'mode': 'all',
        'count': 0,
    },
    'grace': {  # TODO - do admins ever turn this plugin off?
        'dn': ['cn=IPA Graceperiod,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-pluginEnabled',
        ],
        'multivalued': [],
        'label': 'Grace Period Plugin',
        'mode': 'all',
        'count': 0,
    },
    'lockout': {  # TODO - do admins ever turn this plugin off?
        'dn': ['cn=IPA Lockout,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-pluginEnabled',
        ],
        'multivalued': [],
        'label': 'Lockout Plugin',
        'mode': 'all',
        'count': 0,
    },
    'enroll': {  # TODO - might not be needed?
        'dn': ['cn=ipa_enrollment_extop,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-realmtree',
        ],
        'multivalued': [],
        'label': 'Enrollment Plugin',
        'mode': 'all',
        'count': 0,
    },
    'extdom': {  # TODO - might not be needed?
        'dn': ['cn=ipa_extdom_extop,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-basedn',
        ],
        'multivalued': [],
        'label': 'Extdom Extop Plugin',
        'mode': 'all',
        'count': 0,
    },
    'pw_extop': {  # TODO - might not be needed?
        'dn': ['cn=ipa_pwd_extop,cn=plugins,cn=config'],
        'attrs': [
            'nsslapd-realmtree',
        ],
        'multivalued': [],
        'label': 'Password Extop Plugin',
        'mode': 'all',
        'count': 0,
    },
    'dna': {
        'dn': [
            'cn=Posix IDs,cn=Distributed Numeric Assignment Plugin,'
            'cn=plugins,cn=config',
            'cn=Subordinate IDs,cn=Distributed Numeric Assignment '
            'Plugin,cn=plugins,cn=config'
        ],
        'attrs': [
            'dnafilter', 'dnamaxValue', 'dnanextvalue',
            'dnasharedcfgdn', 'dnathreshold', 'dnatype',
            # 'dnaexcludeScope'  # became stricter in newer versions, but
            # migration reverts the scope to bhe more open
        ],
        'multivalued': [],
        'label': 'DNA Plugin',
        'mode': 'production',
        'count': 0,
    },
    'schema_compat': {
        'dn': [
            'cn=Schema Compatibility,cn=plugins,cn=config',
            'cn=users,cn=Schema Compatibility,cn=plugins,cn=config',
            'cn=groups,cn=Schema Compatibility,cn=plugins,cn=config',
            'cn=ng,cn=Schema Compatibility,cn=plugins,cn=config',
            'cn=sudoers,cn=Schema Compatibility,cn=plugins,cn=config',
            'cn=computers,cn=Schema Compatibility,cn=plugins,cn=config',
        ],
        'attrs': [
            'schema-compat-container-group', 'schema-compat-search-base',
            'schema-compat-container-rdn', 'nsslapd-pluginenabled',
        ],
        'multivalued': [
            'schema-compat-entry-attribute', 'schema-compat-ignore-subtree',
            'schema-compat-restrict-subtree',
        ],
        'label': 'Schema Compat Plugin',
        'mode': 'all',
        'count': 0,
    },
    'sasl_map': {
        'dn': [
            'cn=Full Principal,cn=mapping,cn=sasl,cn=config',
            'cn=ID Overridden Principal,cn=mapping,cn=sasl,cn=config',
            'cn=Name Only,cn=mapping,cn=sasl,cn=config',
        ],
        'attrs': [
            'nssaslmapbasedntemplate', 'nssaslmappriority',
            'nssaslmapregexstring', 'nssaslmapfiltertemplate',
        ],
        'multivalued': [],
        'label': 'SASL Map',
        'mode': 'all',
        'count': 0,
    },
    'uuid': {
        'dn': [
            'cn=IPA Unique IDs,cn=IPA UUID,cn=plugins,cn=config',
            'cn=IPK11 Unique IDs,cn=IPA UUID,cn=plugins,cn=config',
        ],
        'attrs': [
            'ipauuidattr', 'ipauuidenforce', 'ipauuidexcludesubtree',
            'ipauuidfilter', 'ipauuidmagicregen', 'ipauuidscope'
        ],
        'multivalued': [],
        'label': 'UUID Plugin',
        'mode': 'all',
        'count': 0,
    },
    'uniqueness': {
        'dn': [
            'cn=uid uniqueness,cn=plugins,cn=config',
            'cn=attribute uniqueness,cn=plugins,cn=config',
            'cn=krbPrincipalName uniqueness,cn=plugins,cn=config',
            'cn=krbCanonicalName uniqueness,cn=plugins,cn=config',
            'cn=ipaUniqueID uniqueness,cn=plugins,cn=config',
            'cn=certificate store subject uniqueness,cn=plugins,cn=config',
            'cn=certificate store issuer/serial uniqueness,cn=plugins,'
            'cn=config',
            'cn=caacl name uniqueness,cn=plugins,cn=config',
            'cn=netgroup uniqueness,cn=plugins,cn=config',
            'cn=sudorule name uniqueness,cn=plugins,cn=config',
            'cn=ipaSubordinateIdEntry ipaOwner uniqueness,cn=plugins,'
            'cn=config',
            'cn=mail uniqueness,cn=plugins,cn=config',
        ],
        'attrs': [
            'uniqueness-across-all-subtrees',
        ],
        'multivalued': [
            'uniqueness-subtrees', 'uniqueness-exclude-subtrees',
            'uniqueness-attribute-name'
        ],
        'label': 'Attr Uniqueness Plugin',
        'mode': 'all',
        'count': 0,
    },
}

#
# This mapping is simliar to above but it handles container entries
# This could be built into the above mapping using the "comma" approach
#
DS_INDEXES = {
    'index': {
        'dn': ',cn=index,cn=userroot,cn=ldbm database,cn=plugins,cn=config',
        'attrs': [
            'nssystemindex',
        ],
        'multivalued': [
            'nsindextype',
            'nsmatchingrule',
        ],
        'label': 'Database Indexes',
        'mode': 'all',
        'count': 0
    },
    'encrypted': {
        'dn': ',cn=encrypted attributes,cn=userroot,cn=ldbm database,'
              'cn=plugins,cn=config',
        'attrs': [
            'nsencryptionalgorithm',
        ],
        'multivalued': [],
        'label': 'Encrypted Attributes',
        'mode': 'all',
        'count': 0
    },
}

#
# This mapping breaks each IPA entry (or type of entry) into its own catagory
# Each catagory, or type, has an objectclass list "oc" and its DIT location
# "subtree".  If the "subtree" starts with a comma "," then it is a container
# of entries, otherwise it's a single entry.  These two are used together to
# identify the entry.
# The "label" and "count" attributes are used for the Summary Report
#
# Some entries use ipaUniqueId as the RDN attribute, this makes comparing
# entries between the remote and local servers problematic. So we need special
# identifying information to find the local entry. In this case we use the
# "alt_id" key which is a dict of an attribute 'attr' and partial base DN
# 'base' - which is expected to end in a comma.
#
DB_OBJECTS = {
    # Plugins
    'automember_def': {
        'oc': ['automemberdefinition'],
        'subtree': ',cn=automember,cn=etc,$SUFFIX',
        'label': 'Automember Definitions',
        'mode': 'all',
        'count': 0,
    },
    'automember_rules': {
        'oc': ['automemberregexrule'],
        'subtree': ',cn=automember,cn=etc,$SUFFIX',
        'label': 'Automember Rules',
        'mode': 'all',
        'count': 0,
    },

    'dna_ranges': {
        'oc': ['ipadomainidrange', 'ipaidrange', 'ipatrustedaddomainrange'],
        'subtree': ',cn=ranges,cn=etc,$SUFFIX',
        'label': 'DNA Ranges',
        'prod_only': False,
        'mode': 'production',
        'count': 0,
    },
    'dna_posix_ids': {
        'oc': ['dnasharedconfig'],
        'subtree': 'cn=posix-ids,cn=dna,cn=ipa,cn=etc,$SUFFIX',
        'label': 'DNA Posix IDs',
        'prod_only': False,
        'mode': 'production',
        'count': 0,
    },
    'dna_sub_ids': {
        'oc': ['dnasharedconfig'],
        'subtree': 'cn=subordinate-ids,cn=dna,cn=ipa,cn=etc,$SUFFIX',
        'label': 'DNA Sub IDs',
        'prod_only': False,
        'mode': 'production',
        'count': 0,
    },
    'mep_templates': {
        'oc': ['meptemplateentry'],
        'subtree': ',cn=templates,cn=managed entries,cn=etc,$SUFFIX',
        'label': 'MEP Templates',
        'mode': 'all',
        'count': 0,
    },
    'mep_defs': {
        'oc': ['extensibleobject'],
        'subtree': ',cn=definitions,cn=managed entries,cn=etc,$SUFFIX',
        'label': 'MEP Defintions',
        'mode': 'all',
        'count': 0,
    },

    # Etc...
    'anon_limits': {
        'oc': [],
        'subtree': 'cn=anonymous-limits,cn=etc,$SUFFIX',
        'label': 'Anonymous Limits',
        'mode': 'all',
        'count': 0,
    },
    'ca': {  # Unknown if this is needed TODO
        'oc': [],
        'subtree': 'cn=ca,$SUFFIX',
        'label': 'CA',
        'mode': 'all',
        'count': 0,
    },
    'ipa_config': {
        'oc': ['ipaconfigobject', 'ipaguiconfig'],
        'subtree': 'cn=ipaconfig,cn=etc,$SUFFIX',
        'special_attrs': [
            # needs special handling, but ipa-server-upgrade rewrites this
            # attribute anyway!
            ('ipausersearchfields', 'list'),
        ],
        'label': 'IPA Config',
        'mode': 'all',
        'count': 0,
    },
    'sysaccounts': {
        'oc': [],
        'subtree': ',cn=sysaccounts,cn=etc,$SUFFIX',
        'label': 'Sysaccounts',
        'mode': 'all',
        'count': 0,
    },
    'topology': {
        'oc': ['iparepltopoconf'],
        'subtree': ',cn=topology,cn=ipa,cn=etc,$SUFFIX',
        'label': 'Topology',
        'mode': 'all',
        'count': 0,
    },
    'certmap': {
        'oc': ['ipacertmapconfigobject'],
        'subtree': 'cn=certmap,$SUFFIX',
        'label': 'Certmap',
        'mode': 'all',
        'count': 0,
    },
    'certmap_rules': {
        'oc': [],
        'subtree': ',cn=certmaprules,cn=certmap,$SUFFIX',
        'label': 'Certmap Rules',
        'mode': 'all',
        'count': 0,
    },
    's4u2proxy': {
        'oc': ['ipakrb5delegationacl', 'groupofprincipals'],
        'subtree': ',cn=s4u2proxy,cn=etc,$SUFFIX',
        'label': 's4u2proxy',
        'mode': 'all',
        'count': 0,
    },
    'passkey_config': {
        'oc': ['ipapasskeyconfigobject'],
        'subtree': 'cn=passkeyconfig,cn=etc,$SUFFIX',
        'label': 'PassKey Config',
        'mode': 'all',
        'count': 0,
    },
    'desktop_profiles': {
        'oc': ['ipadeskprofileconfig'],
        'subtree': 'cn=desktop-profile,$SUFFIX',
        'label': 'Desktop Pofiles',
        'mode': 'all',
        'count': 0,
    },

    # Accounts
    'computers': {
        'oc': ['ipahost'],
        'subtree': ',cn=computers,cn=accounts,$SUFFIX',
        'label': 'Hosts',
        'mode': 'all',
        'count': 0,
    },
    'admin': {
        'oc': ['person'],
        'subtree': 'uid=admin,cn=users,cn=accounts,$SUFFIX',
        'label': 'Admin',
        'mode': 'all',
        'count': 0,
    },
    'users': {
        'oc': ['person'],
        'subtree': ',cn=users,cn=accounts,$SUFFIX',
        'label': 'Users',
        'strip_attrs': [
            'krbprincipalname',
            'krbextradata',
            'krbprincipalkey',
            'krblastpwdchange',
            'krbpasswordexpiration',
            'krblastadminunlock',
            'krblastfailedauth',
            'krbloginfailedcount',
        ],
        'mode': 'all',
        'count': 0,
    },
    'groups': {
        'oc': ['groupofnames', 'posixgroup'],
        'subtree': ',cn=groups,cn=accounts,$SUFFIX',
        'label': 'Groups',
        'mode': 'all',
        'count': 0,
    },
    'roles': {
        'oc': ['groupofnames'],
        'subtree': ',cn=roles,cn=accounts,$SUFFIX',
        'label': 'Roles',
        'mode': 'all',
        'count': 0,
    },
    'host_groups': {
        'oc': ['ipahostgroup'],
        'subtree': ',cn=hostgroups,cn=accounts,$SUFFIX',
        'label': 'Host Groups',
        'mode': 'all',
        'count': 0,
    },
    'services': {  # Contains COS entries - should COS be ignored TODO
        'oc': ['ipaservice'],
        'subtree': ',cn=services,cn=accounts,$SUFFIX',
        'label': 'Services',
        'mode': 'all',
        'count': 0,
    },
    'views': {  # unknown what these entries look like TODO
        'oc': [],
        'subtree': ',cn=views,cn=accounts,$SUFFIX',
        'label': 'Views',
        'mode': 'all',
        'count': 0,
    },
    'ipservices': {  # unknown what these entries look like TODO
        'oc': [],
        'subtree': ',cn=ipservices,cn=accounts,$SUFFIX',
        'label': 'IP Services',
        'mode': 'all',
        'count': 0,
    },
    'subids': {
        'oc': [],
        'subtree': ',cn=subids,cn=accounts,$SUFFIX',
        'label': 'Sub IDs',
        'mode': 'production',
        'alt_id': {
            'attr': 'ipaOwner',
            'isDN': True,
            'base': 'cn=subids,cn=accounts,',
        },
        'count': 0,
    },

    # automount
    'automounts': {
        'oc': [],
        'subtree': ',cn=automount,$SUFFIX',
        'label': 'Automounts',
        'mode': 'all',
        'count': 0,
    },
    'automount_maps': {
        'oc': ['automountmap'],
        'subtree': ',cn=automount,$SUFFIX',
        'label': 'Automount Maps',
        'mode': 'all',
        'count': 0,
    },

    # OTP
    'otp': {
        'oc': [],
        'subtree': ',cn=otp,$SUFFIX',
        'label': 'OTP',
        'mode': 'all',
        'count': 0,
    },
    'otp_config': {
        'oc': ['ipatokenotpconfig'],
        'subtree': 'cn=otp,cn=etc,$SUFFIX',
        'label': 'OTP Config',
        'mode': 'all',
        'count': 0,
    },

    # Realms
    'realms': {
        'oc': ['domainrelatedobject'],
        'subtree': ',cn=realm domains,cn=ipa,cn=etc,$SUFFIX',
        'label': 'Realm',
        'mode': 'all',
        'count': 0,
    },

    # Trusts - not sure if this is useful TODO
    # cn=ad,cn=trusts,#SUFFIX
    'trusts': {
        'oc': [],
        'subtree': ',cn=trusts,$SUFFIX',
        'label': 'Trusts',
        'mode': 'all',
        'count': 0,
    },

    # AD
    'ad': {
        'oc': ['ipantdomainattrs'],
        'subtree': ',cn=ad,cn=etc,$SUFFIX',
        'label': 'AD',
        'mode': 'all',
        'count': 0,
    },

    # Provisioning (staged and deleted users) also COS entries
    'provisioning': {
        'oc': [],
        'subtree': ',cn=accounts,cn=provisioning,$SUFFIX',
        'label': 'Provisioning',
        'mode': 'all',
        'count': 0,
    },

    # PBAC
    'pbac_priv': {
        'oc': ['groupofnames'],
        'subtree': ',cn=privileges,cn=pbac,$SUFFIX',
        'label': 'Privileges',
        'mode': 'all',
        'count': 0,
    },
    'pbac_perms': {
        'oc': ['ipapermission'],
        'subtree': ',cn=permissions,cn=pbac,$SUFFIX',
        'label': 'Permissions',
        'mode': 'all',
        'count': 0,
    },

    # HBAC
    'hbac_services': {
        'oc': ['ipahbacservice'],
        'subtree': ',cn=hbacservices,cn=hbac,$SUFFIX',
        'label': 'HBAC Services',
        'mode': 'all',
        'count': 0,
    },
    'hbac_service_groups': {
        'oc': ['ipahbacservicegroup'],
        'subtree': ',cn=hbacservicegroups,cn=hbac,$SUFFIX',
        'label': 'HBAC Service Groups',
        'mode': 'all',
        'count': 0,
    },
    'hbac_rules': {
        'oc': ['ipahbacrule'],
        'subtree': ',cn=hbac,$SUFFIX',
        'label': 'HBAC Rules',
        'alt_id': {
            'attr': 'cn',
            'base': 'cn=hbac,',
            'isDN': False,
        },
        'mode': 'all',
        'count': 0,
    },

    # Selinux
    'selinux_usermap': {  # Not sure if this is needed, entry is empty  TODO
        'oc': [],
        'subtree': ',cn=usermap,cn=selinux,$SUFFIX',
        'alt_id': {
            'attr': 'cn',
            'base': 'cn=usermap,cn=selinux,',
            'isDN': False,
        },
        'label': 'Selinux Usermaps',
        'mode': 'all',
        'count': 0,
    },

    # Sudo
    'sudo_rules': {
        'oc': ['ipasudorule'],
        'subtree': ',cn=sudorules,cn=sudo,$SUFFIX',
        'label': 'Sudo Rules',
        'alt_id': {
            'attr': 'cn',
            'base': 'cn=sudorules,cn=sudo,',
            'isDN': False,
        },
        'special_attrs': [
            # schema defines sudoOrder as mutlivalued, but we need to treat
            # it as single valued
            ('sudoorder', 'single'),
        ],
        'mode': 'all',
        'count': 0,
    },
    'sudo_cmds': {
        'oc': ['ipasudocmd'],
        'subtree': ',cn=sudocmds,cn=sudo,$SUFFIX',
        'alt_id': {
            'attr': 'sudoCmd',
            'base': 'cn=sudocmds,cn=sudo,',
            'isDN': False,
        },
        'label': 'Sudo Commands',
        'mode': 'all',
        'count': 0,
    },
    'sudo_cmd_groups': {
        'oc': ['ipasudocmdgrp'],
        'subtree': ',cn=sudocmdgroups,cn=sudo,$SUFFIX',
        'label': 'Sudo Command Groups',
        'mode': 'all',
        'count': 0,
    },
    # DNS
    'dns_container': {
        'oc': ['ipadnscontainer', 'nscontainer'],
        'subtree': 'cn=dns,$SUFFIX',
        'label': 'DNS Container',
        'mode': 'all',
        'count': 0,
    },
    'dns_server_container': {
        'oc': ['nscontainer'],
        'subtree': 'cn=servers,cn=dns,$SUFFIX',
        'label': 'DNS Server Container',
        'mode': 'all',
        'count': 0,
    },
    'dns_records': {
        'oc': ['idnsrecord', 'idnszone', 'idnsforwardzone'],
        'subtree': ',cn=dns,$SUFFIX',
        'label': 'DNS Records',
        'mode': 'all',
        'count': 0,
    },
    'dns_servers': {
        'oc': ['idnsServerConfigObject'],
        'subtree': ',cn=servers,cn=dns,$SUFFIX',
        'label': 'DNS Servers',
        'mode': 'all',
        'count': 0,
    },
    # Kerberos
    'krb_realm': {
        'oc': ['krbrealmcontainer'],
        'subtree': ',cn=kerberos,$SUFFIX',
        'label': 'Kerberos Realm',
        'mode': 'all',
        'count': 0,
    },
    'kerberos_policy': {  # principal
        'oc': ['krbticketpolicyaux'],
        'subtree': ',cn=kerberos,$SUFFIX',
        'label': 'Kerberos Policy',
        'mode': 'all',
        'count': 0,
    },
    'krb_pwpolicy': {
        'oc': ['ipapwdpolicy'],
        'subtree': 'cn=global_policy,cn=$REALM,cn=kerberos,$SUFFIX',
        'label': 'Kerberos Password Policy',
        'mode': 'all',
        'count': 0,
    },
    'krb_default_pwppolicy': {
        'oc': ['krbpwdpolicy'],
        'subtree': 'cn=default kerberos service password policy,'
                   'cn=$REALM,cn=kerberos,$SUFFIX',
        'label': 'Kerberos Default Password Policy',
        'mode': 'all',
        'count': 0,
    },

    # Other
    'domain_config': {
        'oc': ['ipadomainlevelconfig'],
        'subtree': 'cn=domain level,cn=ipa,cn=etc,$SUFFIX',
        'label': 'Domain Configuration',
        'mode': 'all',
        'count': 0,
    },
    'net_groups': {
        'oc': ['ipanisnetgroup'],
        'not_oc': ['mepmanagedentry'],
        'subtree': ',cn=ng,cn=alt,$SUFFIX',
        'alt_id': {
            'attr': 'cn',
            'base': 'cn=ng,cn=alt,',
            'isDN': False,
        },
        'label': 'Network Groups',
        'mode': 'all',
        'count': 0,
    },

    # Certificates
    # cn=IPA.LOCAL IPA CA,cn=certificates,cn=ipa,cn=etc,dc=ipademo,dc=local
    'certificate': {
        'oc': ['ipacertificate', 'pkica'],
        'subtree': ',cn=certificates,cn=ipa,cn=etc,$SUFFIX',
        'label': 'CA Certificates',
        'mode': 'all',
        'count': 0,
    },
    'caacls': {
        'oc': ['ipacaacl'],
        'subtree': ',cn=caacls,cn=ca,$SUFFIX',
        'alt_id': {
            'attr': 'cn',
            'base': 'cn=caacls,cn=ca,',
            'isDN': False,
        },
        'label': 'CA Certificate ACLs',
        'mode': 'all',
        'count': 0,
    },
}

DB_EXCLUDE_TREES = [
    'cn=sec,cn=dns,$SUFFIX',
    'cn=custodia,cn=ipa,cn=etc,$SUFFIX',
]

#
# COS can probably be skipped TODO
#
COS = {
    # COS
    'cos_templates': 'cn=cosTemplates,cn=accounts,$SUFFIX',
    'cos_pwpolicy': 'cn=Password Policy,cn=accounts,$SUFFIX',
    # COS Computers
    'cos_computer:templates': 'cn=cosTemplates,cn=computers,cn=accounts,',
    'cos_computer_pwpolicy':
        'cn=Default Password Policy,cn=cosTemplates,cn=computers,cn=accounts,',
    'cos_computer_pwpolicy_entry':
        'cn=Default Password Policy,cn=computers,cn=accounts,',
    # COS Services
    'cos_service_templates': 'cn=cosTemplates,cn=services,cn=accounts,$SUFFIX',
    'cos_service_pwpolicy':
        'cn=Default Password Policy,cn=cosTemplates,cn=services,cn=accounts,',
    'cos_service_pwpolicy_entry':
        'cn=Default Password Policy,cn=services,cn=accounts,',
    # COS Kerberos
    'cos_kerb_realm_templates': 'cn=cosTemplates,cn=$REALM,cn=kerberos,',
    'cos_kerb_realm_pwpolicy':
        'cn=Default Password Policy,cn=cosTemplates,cn=$REALM,cn=kerberos,',
    'cos_kerb_realm_pwpolicy_entry':
        'cn=Default Password Policy,cn=$REALM,cn=kerberos,',
    # COS Sysaccounts
    'cos_sysacct_templates': 'cn=cosTemplates,cn=sysaccounts,cn=etc,',
    'cos_sysacct_pwpolicy':
        'cn=Default Password Policy,cn=cosTemplates,cn=sysaccounts,cn=etc,',
    'cos_sysacct_pwpolicy_entry':
        'cn=Default Password Policy,cn=sysaccounts,cn=etc,',
}
