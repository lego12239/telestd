/**
 * @file dframe.h
 */
#ifndef __DFRAME_H__
#define __DFRAME_H__ 1

#define LINES_CNT 4
#define DATAFRAME_SIZE 165
#define ACTIVITY_THRESHOLD 8
#define SPEAK_TIMEOUT 5

struct dataframe {
	char buf[DATAFRAME_SIZE * 2 + 1];
	char *ptr;
	struct {
		char snd[40];
		unsigned int is_active;
	} lines[4];
};

void dframe_init(struct dataframe *dframe);
int dframe_read(int fd, struct dataframe *dframe);

#endif /* __DFRAME_H__ */
