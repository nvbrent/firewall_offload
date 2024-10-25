/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2024 Nvidia
 */
#include <syslog.h>

#include "nv_opof.h"
#include "nv_opof_util.h"

void opof_enable_protobuf_debugging(const char *filename);

bool nv_opof_log_to_console_enable = false;
int nv_opof_log_mask = LOG_UPTO(LOG_INFO);

void nv_opof_log_open(void)
{
	// Note that LOG_PERROR would be a simpler way to mirror the
	// syslog to the console, but it does not appear to work here.
	openlog("nv_opof", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);
	nv_opof_set_log_level(LOG_INFO);
}

void nv_opof_log(int level, const char *format, ...)
{
	va_list args;
	va_start (args, format);

	if (nv_opof_log_to_console_enable && (nv_opof_log_mask & LOG_MASK(level)))
		vprintf(format, args);
	else
		vsyslog(level, format, args);

	va_end(args);
}

void nv_opof_log_close(void)
{
	closelog();
}

void nv_opof_set_log_level(int level)
{
	nv_opof_log_mask = LOG_UPTO(level);
	setlogmask(LOG_UPTO(level));

	if (level == LOG_DEBUG) {
		opof_enable_protobuf_debugging("/tmp/opof_protobuf.log");
	}
}
