/**
 * @file dframe.c
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include "dframe.h"

extern unsigned int is_debug_mode;

const char dataframe_ssig[5 + 1] = {0x0a, 0xff, 0x0a, 0xff, 0x0a, 0};


static void dbg_dump_data(char *data, unsigned int len)
{
	unsigned int i;
	
	
	if (!is_debug_mode)
		return;
	
	for(i = 0; i < len; i++) {
		fprintf(stderr, "%02hhx ", data[i]);
		if ((i + 1) % 16 == 0)
			fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
}

static int dbg_out(const char *fmt, ...)
{
	int ret;
	va_list ap;
	
	
	if (!is_debug_mode)
		return 0;
	
	va_start(ap, fmt);
	ret = vfprintf(stderr, fmt, ap);
	va_end(ap);
	
	return ret;
}

void dframe_init(struct dataframe *dframe)
{
	unsigned int i;
	
	
	dframe->buf[DATAFRAME_SIZE * 2] = 0;
	dframe->ptr = dframe->buf;

	for(i = 0; i < LINES_CNT; i++)
		dframe->lines[i].is_active = 0;
}

static ssize_t readn(int fd, void *buf, size_t count)
{
	size_t nleft = count;
	ssize_t n;
	
	
	while (nleft > 0) {
		n = read(fd, buf, nleft);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		} else if (n == 0) {
			break;
		}
		buf += n;
		nleft -= n;
	}
	
	return (count - nleft);
}

static const char* sig_search(const char *data, size_t n, const char *sig,
  size_t sn)
{
	unsigned int i, j;
	unsigned int off;
	
	
	j = 0;
	off = 0;
	for(i = 0; i < n; i++) {
		if (data[i] == sig[j]) {
			if (j == 0)
				off = i;
			j++;
			if (j == sn)
				return data + off;
		} else if (j) {
			i = off;
			j = 0;
		}
	}
	
	return NULL;
}

static void dframe_parse(const char *df_raw, struct dataframe *dframe)
{
	int i, j, k;
	
	
	for(i = 0, j = 0; i < DATAFRAME_SIZE - 5; i += LINES_CNT, j++) {
		for(k = 0; k < LINES_CNT; k++) {
			dframe->lines[k].snd[j] = df_raw[i + k];
			if (dframe->lines[k].snd[j] > ACTIVITY_THRESHOLD) {
				dframe->lines[k].is_active = SPEAK_TIMEOUT * 8000;
			} else {
				if (dframe->lines[k].is_active)
					dframe->lines[k].is_active--;
			}
		}
	}
	for(i = 0; i < LINES_CNT; i++)
		dbg_out("%d is_active: %d\n", i, dframe->lines[i].is_active);
}

int dframe_read(int fd, struct dataframe *dframe)
{
	ssize_t n, cnt;
	const char *df_start;
	
	
	dbg_out("dframe_read(): databuf=%p, databuf_ptr=%p\n",
		dframe->buf, dframe->ptr);
	/* read input until we get a complete data frame */
	do {
		cnt = DATAFRAME_SIZE * 2 - (dframe->ptr - dframe->buf);
		n = readn(fd, dframe->ptr, cnt);
		if (n == -1)
			return -1;
		/* Can this situation really be occured? */
		if (n < cnt)
			return 0;
		dbg_out("dframe_read(): read %d bytes\ndatabuf contains:\n", n);
		dbg_dump_data(dframe->buf, DATAFRAME_SIZE * 2);
	
		/* Find dataframe start */
		df_start = sig_search(dframe->buf, DATAFRAME_SIZE * 2,
		  dataframe_ssig, 5);
		dbg_out("dframe_read(): df_start=%p\n", df_start);
		if (!df_start) {
			/* HERE MUST BE LOGGING INSTEAD OF THIS */
			fprintf(stderr, "start signature can't be found\n");
			return -2;
		}
		n = DATAFRAME_SIZE * 2 - (df_start - dframe->buf);
		if (n < DATAFRAME_SIZE) {
			memmove(dframe->buf, df_start, n);
			dframe->ptr = dframe->buf + n;
		}
	} while (n < DATAFRAME_SIZE);
	
	dframe_parse(df_start + 5, dframe);
	dbg_out("qq\n");
	dbg_dump_data(dframe->lines[0].snd, 40);
	
	df_start += DATAFRAME_SIZE;
	n -=  DATAFRAME_SIZE;
	memmove(dframe->buf, df_start, n);
	dframe->ptr = dframe->buf + n;
	
	return 1;
}

