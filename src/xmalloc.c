/**
 * @file xmalloc.c
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <syslog.h>
#include "xmalloc.h"


void* xmalloc(const char *const file, unsigned int line, size_t size)
{
	void *ptr;


	if (size == 0) {
		syslog(LOG_CRIT, "%s: %d: %s", file, line, "Try to malloc zero size");
		exit(EXIT_FAILURE);
	}

	ptr = malloc(size);
	if (!ptr) {
		syslog(LOG_CRIT, "%s: %d: %s", file, line, "Out of memory");
		exit(EXIT_FAILURE);
	}

	return ptr;
}

void* xrealloc(const char *const file, unsigned int line,
               void *ptr, size_t size)
{
	void *new_ptr;


	if (size == 0) {
		syslog(LOG_CRIT, "%s: %d: %s", file, line, "Try to realloc zero size");
		exit(EXIT_FAILURE);
	}

	new_ptr = (void*)realloc(ptr, size);
	if (!new_ptr) {
		syslog(LOG_CRIT, "%s: %d: %s", file, line, "Out of memory");
		exit(EXIT_FAILURE);
	}

	return new_ptr;
}

char* xstrdup(const char *const file, unsigned int line, const char *str)
{
	char *dup_str;


	dup_str = strdup(str);
	if (!dup_str) {
		syslog(LOG_CRIT, "%s: %d: %s", file, line, "Out of memory");
		exit(EXIT_FAILURE);
	}

	return dup_str;
}

char* xstrndup(const char *const file, unsigned int line, const char *str,
               size_t n)
{
	char *dup_str;


	dup_str = strndup(str, n);
	if (!dup_str) {
		syslog(LOG_CRIT, "%s: %d: %s", file, line, "Out of memory");
		exit(EXIT_FAILURE);
	}

	return dup_str;
}

size_t xstrcatf(const char *const file, unsigned int const line,
                char **const dest_ptr, size_t n, const char *const fmt, ...)
{
	va_list ap;


	va_start(ap, fmt);
	n = xvstrcatf(file, line, dest_ptr, n, fmt, ap);
	va_end(ap);
	
	return n;
}

size_t xvstrcatf(const char *const file, unsigned int const line,
                 char **const dest_ptr, size_t n, const char *const fmt,
                 va_list ap_in)
{
	va_list ap;
	size_t len;
	char *dest;
	int ret;


	if (dest_ptr == NULL) {
		syslog(LOG_CRIT, "%s:%d: xstrcatf() dest_ptr == NULL\n", file, line);
		exit(EXIT_FAILURE);
	}

	if ((*dest_ptr == NULL) || (n == 0)) {
		*dest_ptr = NULL;
		n = 0;
		len = 0;
	} else {
		len = strlen(*dest_ptr);
	}
	dest = *dest_ptr + len;
	n -= len;
	
	/* Get a size of generated string */
	va_copy(ap, ap_in);
	ret = vsnprintf(dest, 0, fmt, ap);
	va_end(ap);
	if (ret < 0) {
		syslog(LOG_CRIT, "%s:%d: %s %s", file, line, "vsnprintf_err",
			"Output error\n");
		exit(EXIT_FAILURE);
	}
	if (ret >= n) {
		if (len > (SIZE_MAX - ret - 1)) {
			syslog(LOG_CRIT, "%s:%d: %s %s", file, line, "vsnprintf_err",
		    	"vsnprintf() error: resulting string is more than SIZE_MAX\n");
			exit(EXIT_FAILURE);
		}
		*dest_ptr = (char*)XREALLOC(*dest_ptr, len + ret + 1);
		dest = *dest_ptr + len;
		n = ret + 1;
	}

	/* Append a generated string to a destination one */
	va_copy(ap, ap_in);
	ret = vsnprintf(dest, n, fmt, ap);
	va_end(ap);
	if (ret < 0) {
		syslog(LOG_CRIT, "%s:%d: %s %s", file, line, "vsnprintf_err",
			"Output error\n");
		exit(EXIT_FAILURE);
	}
	if (ret >= n) {
		/* This error must never be occured */
		syslog(LOG_CRIT, "%s:%d: %s %s", file, line, "vsnprintf_err",
			"Needed more size to print a string\n");
		exit(EXIT_FAILURE);
	}
	
	return len + n;
}

void xfree(const char *const file, unsigned int line, void *ptr)
{
	if (!ptr) {
		syslog(LOG_CRIT, "%s: %d: %s", file, line, "Try to free NULL pointer");
		exit(EXIT_FAILURE);
	}

	free(ptr);
}
