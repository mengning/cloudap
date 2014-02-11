/*
 * wpa_supplicant/hostapd / Debug prints
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"

#ifdef CONFIG_DEBUG_SYSLOG
#include <syslog.h>

static int wpa_debug_syslog = 0;
#endif /* CONFIG_DEBUG_SYSLOG */

#ifdef CONFIG_DEBUG_LINUX_TRACING
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

static FILE *wpa_debug_tracing_file = NULL;

#define WPAS_TRACE_PFX "wpas <%d>: "
#endif /* CONFIG_DEBUG_LINUX_TRACING */


int wpa_debug_level = MSG_EXCESSIVE;
int wpa_debug_show_keys = 0;
int wpa_debug_timestamp = 0;




/**
 * wpa_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void wpa_printf(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (level >= wpa_debug_level) {
		vprintf(fmt, ap);
		printf("\n");
	}
	va_end(ap);
}

static void _wpa_hexdump(int level, const char *title, const u8 *buf,
			 size_t len, int show)
{
	size_t i;

#ifdef CONFIG_DEBUG_LINUX_TRACING
	if (wpa_debug_tracing_file != NULL) {
		fprintf(wpa_debug_tracing_file,
			WPAS_TRACE_PFX "%s - hexdump(len=%lu):",
			level, title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(wpa_debug_tracing_file, " [NULL]\n");
		} else if (!show) {
			fprintf(wpa_debug_tracing_file, " [REMOVED]\n");
		} else {
			for (i = 0; i < len; i++)
				fprintf(wpa_debug_tracing_file,
					" %02x", buf[i]);
		}
		fflush(wpa_debug_tracing_file);
	}
#endif /* CONFIG_DEBUG_LINUX_TRACING */

	if (level < wpa_debug_level)
		return;
#ifdef CONFIG_ANDROID_LOG
	{
		const char *display;
		char *strbuf = NULL;
		size_t slen = len;
		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			/* Limit debug message length for Android log */
			if (slen > 32)
				slen = 32;
			strbuf = os_malloc(1 + 3 * slen);
			if (strbuf == NULL) {
				wpa_printf(MSG_ERROR, "wpa_hexdump: Failed to "
					   "allocate message buffer");
				return;
			}

			for (i = 0; i < slen; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		__android_log_print(wpa_to_android_level(level),
				    ANDROID_LOG_NAME,
				    "%s - hexdump(len=%lu):%s%s",
				    title, (long unsigned int) len, display,
				    len > slen ? " ..." : "");
		os_free(strbuf);
		return;
	}
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_SYSLOG
	if (wpa_debug_syslog) {
		const char *display;
		char *strbuf = NULL;

		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			strbuf = os_malloc(1 + 3 * len);
			if (strbuf == NULL) {
				wpa_printf(MSG_ERROR, "wpa_hexdump: Failed to "
					   "allocate message buffer");
				return;
			}

			for (i = 0; i < len; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		syslog(syslog_priority(level), "%s - hexdump(len=%lu):%s",
		       title, (unsigned long) len, display);
		os_free(strbuf);
		return;
	}
#endif /* CONFIG_DEBUG_SYSLOG */
	wpa_debug_print_timestamp();
#ifdef CONFIG_DEBUG_FILE
	if (out_file) {
		fprintf(out_file, "%s - hexdump(len=%lu):",
			title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(out_file, " [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				fprintf(out_file, " %02x", buf[i]);
		} else {
			fprintf(out_file, " [REMOVED]");
		}
		fprintf(out_file, "\n");
	} else {
#endif /* CONFIG_DEBUG_FILE */
	printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
	if (buf == NULL) {
		printf(" [NULL]");
	} else if (show) {
		for (i = 0; i < len; i++)
			printf(" %02x", buf[i]);
	} else {
		printf(" [REMOVED]");
	}
	printf("\n");
#ifdef CONFIG_DEBUG_FILE
	}
#endif /* CONFIG_DEBUG_FILE */
#endif /* CONFIG_ANDROID_LOG */
}

void wpa_hexdump(int level, const char *title, const u8 *buf, size_t len)
{
	_wpa_hexdump(level, title, buf, len, 1);
}