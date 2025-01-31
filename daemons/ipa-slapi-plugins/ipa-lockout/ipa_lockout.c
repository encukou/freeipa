/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Copyright (C) 2010-2023 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

/**
 * IPA Lockout plug-in
 *
 * Update the Kerberos lockout variables on LDAP binds.
 *
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "slapi-plugin.h"
#include "nspr.h"
#include <krb5.h>

#include "util.h"

#define IPALOCKOUT_PLUGIN_NAME "ipa-lockout-plugin"
#define IPALOCKOUT_PLUGIN_VERSION 0x00010000

#define IPA_PLUGIN_NAME IPALOCKOUT_PLUGIN_NAME

#define IPALOCKOUT_FEATURE_DESC      "IPA Lockout"
#define IPALOCKOUT_PLUGIN_DESC       "IPA Lockout plugin"
#define IPALOCKOUT_POSTOP_DESC       "IPA Lockout postop plugin"
#define IPALOCKOUT_PREOP_DESC        "IPA Lockout preop plugin"

static Slapi_PluginDesc pdesc = {
    IPALOCKOUT_FEATURE_DESC,
    "Red Hat, Inc.",
    "1.0",
    IPALOCKOUT_PLUGIN_DESC
};

struct ipa_context {
    bool disable_last_success;
    bool disable_lockout;
};

static void *_PluginID = NULL;
static char *_PluginDN = NULL;

static int g_plugin_started = 0;

static struct ipa_context *global_ipactx = NULL;

static char *ipa_global_policy = NULL;

#define GENERALIZED_TIME_LENGTH 15

/**
 *
 * management functions
 *
 */
int ipalockout_init(Slapi_PBlock * pb);
static int ipalockout_start(Slapi_PBlock * pb);
static int ipalockout_close(Slapi_PBlock * pb);
static int ipalockout_postop_init(Slapi_PBlock * pb);
static int ipalockout_preop_init(Slapi_PBlock * pb);

/**
 *
 * the ops (where the real work is done)
 *
 */
static int ipalockout_postop(Slapi_PBlock *pb);
static int ipalockout_preop(Slapi_PBlock *pb);

/**
 *
 * Get the plug-in version
 *
 */
int ipalockout_version(void)
{
    return IPALOCKOUT_PLUGIN_VERSION;
}

/**
 * Plugin identity mgmt
 */
void setPluginID(void *pluginID)
{
    _PluginID = pluginID;
}

void *getPluginID(void)
{
    return _PluginID;
}

void setPluginDN(char *pluginDN)
{
    _PluginDN = pluginDN;
}

char *getPluginDN(void)
{
    return _PluginDN;
}

static int
ipalockout_get_global_config(struct ipa_context *ipactx)
{
    Slapi_Value *value = NULL;
    Slapi_Attr *attr = NULL;
    char *dn = NULL;
    char *basedn = NULL;
    char *realm = NULL;
    Slapi_DN *sdn;
    Slapi_Entry *config_entry;
    krb5_context krbctx = NULL;
    krb5_error_code krberr;
    int ret;

    /* Get cn=config so we can get the default naming context */
    sdn = slapi_sdn_new_dn_byref("cn=config");

    ret = slapi_search_internal_get_entry(sdn, NULL, &config_entry,
              getPluginID());

    slapi_sdn_free(&sdn);

    if (ret) {
        goto done;
    }

    basedn = slapi_entry_attr_get_charptr(config_entry,
        "nsslapd-defaultnamingcontext");

    slapi_entry_free(config_entry);

    if (!basedn) {
        goto done;
    }

    krberr = krb5_init_context(&krbctx);
    if (krberr) {
        LOG_FATAL("krb5_init_context failed (%d)\n", krberr);
        /* Yes, we failed, but it is because /etc/krb5.conf doesn't exist
         * or is misconfigured. Start up in a degraded mode.
         */
    } else {
        krberr = krb5_get_default_realm(krbctx, &realm);
        if (krberr) {
            LOG_FATAL("Failed to get default realm (%d)\n", krberr);
        } else {
            ipa_global_policy =
                slapi_ch_smprintf("cn=global_policy,cn=%s,cn=kerberos,%s",
                                  realm, basedn);
            if (!ipa_global_policy) {
                LOG_OOM();
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }
        }
    }

    ret = asprintf(&dn, "cn=ipaConfig,cn=etc,%s", basedn);
    if (ret == -1) {
        LOG_OOM();
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    sdn = slapi_sdn_new_dn_byref(dn);

    ret = slapi_search_internal_get_entry(sdn, NULL, &config_entry,
              getPluginID());

    slapi_sdn_free(&sdn);

    if (ret) {
        goto done;
    }

    ret = slapi_entry_attr_find(config_entry, "ipaConfigString", &attr);
    if (ret == -1) {
        /* no config, nothing to do */
        ret = 0;
        goto done;
    }

    ret = slapi_attr_first_value(attr, &value);
    while (ret != -1) {
        const struct berval *val;

        val = slapi_value_get_berval(value);
        if (!val) {
            ret = LDAP_OPERATIONS_ERROR;
            slapi_value_free(&value);
            goto done;
        }

        if (strncasecmp("KDC:Disable Last Success",
                        val->bv_val, val->bv_len) == 0) {
            ipactx->disable_last_success = true;
        }
        else if (strncasecmp("KDC:Disable Lockout",
                        val->bv_val, val->bv_len) == 0) {
            ipactx->disable_lockout = true;
        }

        ret = slapi_attr_next_value(attr, ret, &value);
    }
    slapi_value_free(&value);

    ret = 0;

done:
    if (config_entry)
        slapi_entry_free(config_entry);
    free(realm);
    krb5_free_context(krbctx);
    free(dn);
    free(basedn);
    return ret;
}

int ipalockout_getpolicy(Slapi_Entry *target_entry, Slapi_Entry **policy_entry,
                         Slapi_ValueSet** values, char **actual_type_name,
                         const char **policy_dn, int *attr_free_flags,
                         char **errstr)
{
    int ldrc = 0;
    int type_name_disposition = 0;
    Slapi_DN *pdn = NULL;

    /* Only continue if there is a password policy */
    ldrc = slapi_vattr_values_get(target_entry, "krbPwdPolicyReference",
                                values,
                                &type_name_disposition, actual_type_name,
                                SLAPI_VIRTUALATTRS_REQUEST_POINTERS,
                                attr_free_flags);
    if (ldrc == 0) {
        Slapi_Value *sv = NULL;

        if (values != NULL) {
            slapi_valueset_first_value(*values, &sv);
            *policy_dn = slapi_value_get_string(sv);
        }
    } else {
        *policy_dn = ipa_global_policy;
    }

    if (*policy_dn == NULL) {
        LOG_TRACE("No kerberos password policy\n");
        return LDAP_SUCCESS;
    } else {
        pdn = slapi_sdn_new_dn_byref(*policy_dn);
        ldrc = slapi_search_internal_get_entry(pdn, NULL, policy_entry,
                getPluginID());
        slapi_sdn_free(&pdn);
        if (ldrc != LDAP_SUCCESS) {
            LOG_FATAL("Failed to retrieve entry \"%s\": %d\n", *policy_dn, ldrc);
            *errstr = "Failed to retrieve account policy.";
            return LDAP_OPERATIONS_ERROR;
        }
    }

    return LDAP_SUCCESS;
}

int
ipalockout_init(Slapi_PBlock *pb)
{
    int status = EOK;
    char *plugin_identity = NULL;

    LOG_TRACE("--in-->\n");

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_identity);
    PR_ASSERT(plugin_identity);
    setPluginID(plugin_identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *) ipalockout_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) ipalockout_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_register_plugin("postoperation",
                              1,
                              "ipalockout_init",
                              ipalockout_postop_init,
                              IPALOCKOUT_POSTOP_DESC,
                              NULL,
                              plugin_identity
        ) ||
        slapi_register_plugin("preoperation",
                              1,
                              "ipalockout_init",
                              ipalockout_preop_init,
                              IPALOCKOUT_PREOP_DESC,
                              NULL,
                              plugin_identity
        )
        ) {
        LOG_FATAL("failed to register plugin\n");
        status = EFAIL;
    }

    LOG_TRACE("<--out--\n");
    return status;
}

static int
ipalockout_postop_init(Slapi_PBlock *pb)
{
    int status = EOK;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_BIND_FN,
                         (void *) ipalockout_postop) != 0) {
        status = EFAIL;
    }

    return status;
}

static int
ipalockout_preop_init(Slapi_PBlock *pb)
{
    int status = EOK;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN,
                         (void *) ipalockout_preop) != 0) {
        status = EFAIL;
    }

    return status;
}

static int
ipalockout_start(Slapi_PBlock * pb)
{
    LOG_TRACE("--in-->\n");

    /* Check if we're already started */
    if (g_plugin_started) {
        goto done;
    }

    g_plugin_started = 1;

    global_ipactx = (struct ipa_context *)malloc(sizeof(*global_ipactx));
    global_ipactx->disable_last_success = false;
    global_ipactx->disable_lockout = false;
    ipalockout_get_global_config(global_ipactx);

    LOG("ready for service\n");
    LOG_TRACE("<--out--\n");

done:
    return EOK;
}

static int
ipalockout_close(Slapi_PBlock * pb)
{
    LOG_TRACE( "--in-->\n");

    slapi_ch_free_string(&ipa_global_policy);

    LOG_TRACE("<--out--\n");

    return EOK;
}

/*
 * In the post-operation we know whether the bind was successful or not
 * so here we handle updating the Kerberos lockout policy attributes.
 */
static int ipalockout_postop(Slapi_PBlock *pb)
{
    char *dn = NULL;
    const char *policy_dn = NULL;
    Slapi_Entry *target_entry = NULL;
    Slapi_Entry *policy_entry = NULL;
    Slapi_DN *sdn = NULL;
    Slapi_PBlock *pbtm = NULL;
    Slapi_Mods *smods = NULL;
    Slapi_Value *objectclass = NULL;
    char *errstr = NULL;
    int ldrc, rc = 0;
    int ret = LDAP_SUCCESS;
    unsigned long failedcount = 0;
    long old_failedcount;
    char failedcountstr[32];
    char *failedstr = NULL;
    int failed_bind = 0;
    unsigned int lockout_duration = 0;
    unsigned int max_fail = 0;
    struct tm utctime;
    time_t time_now;
    char timestr[GENERALIZED_TIME_LENGTH+1];
    unsigned int failcnt_interval = 0;
    char *lastfail = NULL;
    int tries = 0;
    int failure = 1;
    char *actual_type_name = NULL;
    int attr_free_flags = 0;
    Slapi_ValueSet *values = NULL;

    LOG_TRACE("--in-->\n");

    /* Just bail if we aren't ready to service requests yet. */
    if (!g_plugin_started) {
        goto done;
    }

    if (global_ipactx->disable_lockout) {
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_RESULT_CODE, &rc);

    /* free the dn here */
    if (slapi_pblock_get(pb, SLAPI_CONN_DN, &dn) != 0) {
        LOG_FATAL("Error retrieving bind DN\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* dn will be NULL on failed auth, get the target instead */
    /* don't free this dn */
    if (dn == NULL && rc != LDAP_SUCCESS) {
        failed_bind = 1;
        if (slapi_pblock_get(pb, SLAPI_BIND_TARGET, &dn) != 0) {
            LOG_FATAL("Error retrieving target DN\n");
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }
    }

    /* Client is anonymously bound */
    if (dn == NULL) {
        LOG_TRACE("anonymous bind\n");
        goto done;
    }

    /* Get the entry */
    sdn = slapi_sdn_new_dn_byref(dn);
    if (sdn == NULL) {
        LOG_OOM();
        errstr = "Out of memory.\n";
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ldrc = slapi_search_internal_get_entry(sdn, NULL, &target_entry,
            getPluginID());

    if (ldrc != LDAP_SUCCESS) {
            LOG_TRACE("Failed to retrieve entry \"%s\": %d\n", dn, ldrc);
            goto done;
    }

    /* Only update kerberos principal entries */
    objectclass = slapi_value_new_string("krbPrincipalAux");
    if ((slapi_entry_attr_has_syntax_value(target_entry, SLAPI_ATTR_OBJECTCLASS, objectclass)) != 1) {
        LOG_TRACE("Not a kerberos user\n");
        slapi_value_free(&objectclass);
        goto done;
    }
    slapi_value_free(&objectclass);

    ldrc = ipalockout_getpolicy(target_entry, &policy_entry,
                                &values, &actual_type_name,
                                &policy_dn, &attr_free_flags,
                                &errstr);
    if (ldrc != LDAP_SUCCESS || policy_dn == NULL) {
        goto done;
    }

    max_fail = slapi_entry_attr_get_uint(policy_entry, "krbPwdMaxFailure");
    lockout_duration = slapi_entry_attr_get_uint(policy_entry, "krbPwdLockoutDuration");
    failedcount = slapi_entry_attr_get_ulong(target_entry, "krbLoginFailedCount");
    old_failedcount = failedcount;

    /* Fetch the string value for krbLoginFailedCount to see if the attribute
     * exists in LDAP at all. We get a 0 if it doesn't exist as a long so we
     * don't know whether to try delete the existing value later
     */
    failedstr = slapi_entry_attr_get_charptr(target_entry, "krbLoginFailedCount");
    failcnt_interval = slapi_entry_attr_get_uint(policy_entry, "krbPwdFailureCountInterval");
    lastfail = slapi_entry_attr_get_charptr(target_entry, "krbLastFailedAuth");
    time_now = time(NULL);
    if (lastfail != NULL) {
        struct tm tm;
        int res = 0;

        memset(&tm, 0, sizeof(struct tm));
        res = sscanf(lastfail,
                     "%04u%02u%02u%02u%02u%02u",
                     &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

        if (res == 6) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;

            if (failedcount >= max_fail) {
                if ((lockout_duration == 0) ||
                    (time_now < timegm(&tm) + lockout_duration)) {
                    /* Within lockout duration */
                    LOG_ALERT("User %s is locked out. Too many failed authentication attempts.\n", dn);
                    goto done;
                }
            }
            if (time_now > timegm(&tm) + failcnt_interval) {
                /* Not within lockout duration, outside of fail interval */
                failedcount = 0;
            }
        }
    }

    while (tries < 5) {
        smods = slapi_mods_new();

        /* On failures try very hard to update the entry so that failures
         * are counted properly. This involves doing a DELETE of the value
         * we expect and an ADD of the new one in the same update. If the
         * record has changed while we were handling the request our
         * update will fail and we will try again.
         *
         * On a successful bind just do a replace and set failurecount to 0.
         */
        if (failed_bind) {
            if (failedcount < max_fail) {
                PR_snprintf(failedcountstr, sizeof(failedcountstr), "%lu", old_failedcount);
                if (failedstr != NULL) {
                    slapi_mods_add_string(smods, LDAP_MOD_DELETE, "krbLoginFailedCount", failedcountstr);
                }
                failedcount += 1;
                PR_snprintf(failedcountstr, sizeof(failedcountstr), "%lu", failedcount);
                slapi_mods_add_string(smods, LDAP_MOD_ADD, "krbLoginFailedCount", failedcountstr);
                if (lastfail) {
                    slapi_mods_add_string(smods, LDAP_MOD_DELETE, "krbLastFailedAuth", lastfail);
                }
                if (!gmtime_r(&(time_now), &utctime)) {
                    errstr = "failed to parse current date (buggy gmtime_r ?)\n";
                    LOG_FATAL("%s", errstr);
                    ret = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                strftime(timestr, GENERALIZED_TIME_LENGTH+1,
                     "%Y%m%d%H%M%SZ", &utctime);
                slapi_mods_add_string(smods, LDAP_MOD_ADD, "krbLastFailedAuth", timestr);
            }
        } else {
            if (old_failedcount != 0) {
                PR_snprintf(failedcountstr, sizeof(failedcountstr), "%lu", 0L);
                slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLoginFailedCount", failedcountstr);
            }
            if (!global_ipactx->disable_last_success) {
                time_now = time(NULL);
                if (!gmtime_r(&(time_now), &utctime)) {
                    errstr = "failed to parse current date (buggy gmtime_r ?)\n";
                    LOG_FATAL("%s", errstr);
                    ret = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                strftime(timestr, GENERALIZED_TIME_LENGTH+1,
                     "%Y%m%d%H%M%SZ", &utctime);
                slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLastSuccessfulAuth", timestr);
            }
        }

        if (slapi_mods_get_num_mods(smods) == 0) {
            LOG_TRACE("No account modification required\n");
            goto done;
        }

        pbtm = slapi_pblock_new();
        slapi_modify_internal_set_pb (pbtm, slapi_entry_get_dn_const(target_entry),
        slapi_mods_get_ldapmods_byref(smods),
        NULL, /* Controls */
        NULL, /* UniqueID */
        getPluginID(), /* PluginID */
        0); /* Flags */

        slapi_modify_internal_pb (pbtm);
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);

        if (rc != LDAP_SUCCESS) {
            LOG_TRACE("WARNING: modify error %d on entry '%s'\n",
                      rc, slapi_entry_get_dn_const(target_entry));

            ldrc = slapi_search_internal_get_entry(sdn, NULL, &target_entry,
                    getPluginID());

            if (ldrc != LDAP_SUCCESS) {
                LOG_FATAL("Failed to retrieve entry \"%s\": %d\n", dn, ldrc);
                goto done;
            }
            slapi_mods_free(&smods);
            slapi_pblock_destroy(pbtm);
            if (lastfail) slapi_ch_free_string(&lastfail);
            smods = NULL;
            pbtm = NULL;
            lastfail = NULL;
            tries += 1;
        } else {
            LOG_TRACE("<= apply mods: Successful\n");
            failure = 0;
            break;
        }
    } /* while */

    if (failure) {
        LOG_FATAL("Unable to change lockout attributes\n");
        ret = LDAP_OPERATIONS_ERROR;
    }

done:
    if (!failed_bind && dn != NULL) slapi_ch_free_string(&dn);
    slapi_entry_free(target_entry);
    slapi_entry_free(policy_entry);
    if (values != NULL) {
        slapi_vattr_values_free(&values, &actual_type_name, attr_free_flags);
    }
    if (sdn) slapi_sdn_free(&sdn);
    if (lastfail) slapi_ch_free_string(&lastfail);
    if (pbtm) slapi_pblock_destroy(pbtm);
    if (smods) slapi_mods_free(&smods);
    if (failedstr) slapi_ch_free_string(&failedstr);

    LOG("postop returning %d: %s\n", ret, errstr ? errstr : "success\n");

    if (ret) {
        slapi_send_ldap_result(pb, ret, NULL, errstr, 0, NULL);
    }

    LOG_TRACE("<--out--\n");

    return (ret == 0 ? EOK : EFAIL);
}

/*
 * In the pre-op stage the bind hasn't occurred yet. It is here that
 * we do the lockout enforcement.
 */
static int ipalockout_preop(Slapi_PBlock *pb)
{
    char *dn = NULL;
    const char *policy_dn = NULL;
    Slapi_Entry *target_entry = NULL;
    Slapi_Entry *policy_entry = NULL;
    Slapi_DN *sdn = NULL;
    Slapi_Value *objectclass = NULL;
    char *errstr = NULL;
    int ldrc = 0;
    int ret = LDAP_SUCCESS;
    unsigned long failedcount = 0;
    time_t time_now;
    unsigned int max_fail = 0;
    unsigned int lockout_duration = 0;
    time_t last_failed = 0;
    char *lastfail = NULL;
    char *unlock_time = NULL;
    char *actual_type_name = NULL;
    int attr_free_flags = 0;
    Slapi_ValueSet *values = NULL;

    LOG_TRACE("--in-->\n");

    /* Just bail if we aren't ready to service requests yet. */
    if (!g_plugin_started) {
        goto done;
    }

    if (global_ipactx->disable_lockout) {
        goto done;
    }

    if (slapi_pblock_get(pb, SLAPI_BIND_TARGET, &dn) != 0) {
        LOG_FATAL("Error retrieving target DN\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* Client is anonymously bound */
    if (dn == NULL) {
        LOG_TRACE("anonymous bind\n");
        goto done;
    }

    /* Get the entry */
    sdn = slapi_sdn_new_dn_byref(dn);
    if (sdn == NULL) {
        LOG_OOM();
        errstr = "Out of memory.\n";
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ldrc = slapi_search_internal_get_entry(sdn, NULL, &target_entry,
            getPluginID());

    if (ldrc != LDAP_SUCCESS) {
        LOG_TRACE("Failed to retrieve entry \"%s\": %d\n", dn, ldrc);
        goto done;
    }

    /* Only handle kerberos principal entries */
    objectclass = slapi_value_new_string("krbPrincipalAux");
    if ((slapi_entry_attr_has_syntax_value(target_entry, SLAPI_ATTR_OBJECTCLASS, objectclass)) != 1) {
        LOG_TRACE("Not a kerberos user\n");
        slapi_value_free(&objectclass);
        goto done;
    }
    slapi_value_free(&objectclass);

    ldrc = ipalockout_getpolicy(target_entry, &policy_entry,
                                &values, &actual_type_name,
                                &policy_dn, &attr_free_flags,
                                &errstr);
    if (ldrc != LDAP_SUCCESS || policy_dn == NULL) {
        goto done;
    }

    failedcount = slapi_entry_attr_get_ulong(target_entry, "krbLoginFailedCount");
    time_now = time(NULL);
    lockout_duration = slapi_entry_attr_get_uint(policy_entry, "krbPwdLockoutDuration");

    lastfail = slapi_entry_attr_get_charptr(target_entry, "krbLastFailedAuth");
    unlock_time = slapi_entry_attr_get_charptr(target_entry, "krbLastAdminUnlock");
    if (lastfail != NULL) {
        struct tm tm;
        int res = 0;

        memset(&tm, 0, sizeof(struct tm));
        res = sscanf(lastfail,
                     "%04u%02u%02u%02u%02u%02u",
                     &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

        if (res == 6) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;

            last_failed = timegm(&tm);
        }
    }

    if (lastfail != NULL && unlock_time != NULL) {
        time_t unlock;
        struct tm tm;
        int res = 0;

        memset(&tm, 0, sizeof(struct tm));
        res = sscanf(unlock_time,
                     "%04u%02u%02u%02u%02u%02u",
                     &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

        if (res == 6) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;

            unlock = timegm(&tm);
            if (last_failed <= unlock) {
                /* Administratively unlocked */
                goto done;
            }
        }
        slapi_ch_free_string(&unlock_time);
    }

    max_fail = slapi_entry_attr_get_uint(policy_entry, "krbPwdMaxFailure");
    if (max_fail == 0) {
        goto done;
    }

    if (failedcount >= max_fail) {
        if (lockout_duration == 0) {
            errstr = "Entry permanently locked.\n";
            LOG_PWDPOLICY("Entry '%s' is permanently locked.\n", dn);
            ret = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        if (time_now < last_failed + lockout_duration) {
            /* Too many failures */
            LOG_PWDPOLICY("Too many failed logins for '%s'. %lu out of %d\n",
                          dn, failedcount, max_fail);
            errstr = "Too many failed logins.\n";
            ret = LDAP_UNWILLING_TO_PERFORM;
        }
    }

done:
    if (lastfail) slapi_ch_free_string(&lastfail);
    slapi_entry_free(target_entry);
    slapi_entry_free(policy_entry);
    if (values != NULL) {
        slapi_vattr_values_free(&values, &actual_type_name, attr_free_flags);
    }
    if (sdn) slapi_sdn_free(&sdn);

    LOG("preop returning %d: %s\n", ret, errstr ? errstr : "success\n");

    if (ret) {
        slapi_send_ldap_result(pb, ret, NULL, errstr, 0, NULL);
    }

    LOG_TRACE("<--out--\n");

    return (ret == 0 ? EOK : EFAIL);
}
