/**
 * @file xmalloc.h
 */
#ifndef __XMALLOC_H__
#define __XMALLOC_H__ 1

#include <stdarg.h>

#define XMALLOC(size) xmalloc(__FILE__, __LINE__, (size))
#define XREALLOC(ptr, size) xrealloc(__FILE__, __LINE__, (ptr), (size))
#define XSTRDUP(str) xstrdup(__FILE__, __LINE__, (str))
#define XSTRNDUP(str, n) xstrndup(__FILE__, __LINE__, (str), (n))
#define XSTRCATF(str_ptr, n, fmt, ...) xstrcatf(__FILE__, __LINE__, (str_ptr),\
        (n), (fmt), ##__VA_ARGS__)
#define XVSTRCATF(str_ptr, n, fmt, ap) xvstrcatf(__FILE__, __LINE__, (str_ptr),\
        (n), (fmt), (ap))
#define XFREE(ptr) xfree(__FILE__, __LINE__, (ptr))


void* xmalloc(const char *const file, unsigned int line, size_t size);
void* xrealloc(const char *const file, unsigned int line,
	       void *ptr, size_t size);
char* xstrdup(const char *const file, unsigned int line, const char *str);
char* xstrndup(const char *const file, unsigned int line, const char *str,
	       size_t n);
size_t xstrcatf(const char *const file, unsigned int const line,
        char **const dest_ptr, size_t n, const char *const fmt, ...);
size_t xvstrcatf(const char *const file, unsigned int const line,
        char **const dest_ptr, size_t n, const char *const fmt, va_list ap);
void xfree(const char *const file, unsigned int line, void *ptr);


#endif /* __XMALLOC_H__ */
