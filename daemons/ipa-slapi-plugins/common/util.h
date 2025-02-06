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

#pragma once

#define EOK 0
#define EFAIL -1

#include <stdint.h>
#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#define log_func discard_const(__func__)

#define LOG_PLUGIN_NAME(NAME, fmt, ...) \
    slapi_log_error(SLAPI_LOG_PLUGIN, \
                    NAME, \
                    fmt, ##__VA_ARGS__)

#define LOG(fmt, ...) \
    LOG_PLUGIN_NAME(IPA_PLUGIN_NAME, fmt, ##__VA_ARGS__)

#define LOG_CONFIG_NAME(NAME, fmt, ...) \
    slapi_log_error(SLAPI_LOG_CONFIG, \
                    NAME, \
                    fmt, ##__VA_ARGS__)

#define LOG_CONFIG(fmt, ...) \
    LOG_CONFIG_NAME(IPA_PLUGIN_NAME, fmt, ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) \
    slapi_log_error(SLAPI_LOG_FATAL, log_func, \
                    "[file %s, line %d]: " fmt, \
                    __FILE__, __LINE__, ##__VA_ARGS__)

#define LOG_ALERT(fmt, ...) \
    slapi_log_error(SLAPI_LOG_ALERT, log_func, fmt, ##__VA_ARGS__)

#define LOG_PWDPOLICY(fmt, ...) \
    slapi_log_error(SLAPI_LOG_PWDPOLICY, log_func, fmt, ##__VA_ARGS__)

/* "Trace" logging is very expensive and should be avoided/replaced. TBD */
#define LOG_TRACE(fmt, ...) \
    slapi_log_error(SLAPI_LOG_TRACE, log_func, fmt, ##__VA_ARGS__)

#define LOG_OOM() LOG_FATAL("Out of Memory!\n")
