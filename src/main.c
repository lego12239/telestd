#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <syslog.h>
#include "xmalloc.h"
#include "dframe.h"


#define VERSION "0.1.0"

#define PATH_MAX 1024
#define DST_FNAME_LEN 22
#define LINES_CNT 4

unsigned int is_debug_mode, is_foreground, is_syslog = 1, dst_file_max_len;
char *dst_dir, *src_file, *pidfile, *script_file;

struct dataframe dataframe;
unsigned int src_is_tty;
struct {
	int fd;
	char fname[DST_FNAME_LEN];
	unsigned int written_cnt;
} lines[LINES_CNT];
char dst_file[PATH_MAX];


void log_msg(int priority, const char *fmt, ...)
{
	va_list ap;
	
	
	va_start(ap, fmt);
	if (!is_syslog) {
		vfprintf(stderr, fmt, ap);
	} else {
		vsyslog(priority, fmt, ap);
	}
	va_end(ap);
}

void _log_stop_msg(void)
{
	log_msg(LOG_INFO, "stopped\n");
}

static void on_sigchld(void)
{
	pid_t pid;
	
	
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0);
}

static void sighdlr(int signum, siginfo_t *si, void *_a)
{
	switch (signum) {
	case SIGHUP:
	case SIGTERM:
	case SIGINT:
	case SIGQUIT:
		log_msg(LOG_INFO, "received signal %d - terminating\n", signum);
		exit(EXIT_SUCCESS);
		break;
	case SIGCHLD:
		on_sigchld();
		return;
		break;
	default:
		break;
	}
	log_msg(LOG_INFO, "received signal %d, code - %d - ignoring\n",
		signum, si->si_code);
}

void output_version(void)
{
	printf("telestd %s\n", VERSION);
}

void output_help(void)
{
	printf(
		"Usage: telestd [OPTIONS] DEVICE\n\n"
		"Read a sound data from DEVICE and save it in a specified\n"
		"directory\n\n"
		" -h  show this help\n"
		" -v  show a version\n"
		" -d  turn on a dataframe debug mode\n"
		" -f  works foreground, do not daemonize\n"
		" -m MINUTES\n"
		"     a maximum length in minutes, when a current sound file\n"
		"     is closed and new one is opened\n"
		" -l FACILITY\n"
		"     a log facility, one of daemon, local0..local7, syslog, user\n"
		"     user by default\n"
		" -p PIDFILE\n"
		"     a pid file name\n"
		" -o DIRECTORY\n"
		"     output directory\n"
		"     . by default\n"
		" -s HOOK_SCRIPT_FILE\n"
		"     a file that will be executed on a sound file close\n"
		"     with a sound file name as a first argument\n\n"
		"-d works only if -f is specified.\n"
		"If -f is specified, then all log messages output to stderr instead\n"
		"of syslog.\n");
}

void open_syslog(const char *facility)
{
	int syslog_facility;
	
	
	if (strcmp(facility, "daemon") == 0)
		syslog_facility = LOG_DAEMON;
	else if (strcmp(facility, "local0") == 0)
		syslog_facility = LOG_LOCAL0;
	else if (strcmp(facility, "local1") == 0)
		syslog_facility = LOG_LOCAL1;
	else if (strcmp(facility, "local2") == 0)
		syslog_facility = LOG_LOCAL2;
	else if (strcmp(facility, "local3") == 0)
		syslog_facility = LOG_LOCAL3;
	else if (strcmp(facility, "local4") == 0)
		syslog_facility = LOG_LOCAL4;
	else if (strcmp(facility, "local5") == 0)
		syslog_facility = LOG_LOCAL5;
	else if (strcmp(facility, "local6") == 0)
		syslog_facility = LOG_LOCAL6;
	else if (strcmp(facility, "local7") == 0)
		syslog_facility = LOG_LOCAL7;
	else if (strcmp(facility, "syslog") == 0)
		syslog_facility = LOG_SYSLOG;
	else
		syslog_facility = LOG_USER;
	
	openlog("telestd", LOG_PID, syslog_facility);
}

/*
 * Write error messages only to stderr. So, must be used only in
 * process_opts().
 */
char* mk_abs_path(const char *path)
{
	char *p;
	size_t len;
	
	
	if (!path)
		return NULL;
	
	if (path[0] == '/')
		return XSTRDUP(path);
	
	len = 1 + strlen(path);  /* "/" + path */
	if ((len + 1) >= PATH_MAX) {
		fprintf(stderr, "Absolute path maked from '%s' is longer than %d\n",
		  path, PATH_MAX);
		exit(EXIT_FAILURE);
	}
	
	p = (char*)XMALLOC(PATH_MAX);
	len = PATH_MAX - len;
	if (!getcwd(p, len)) {
		if (errno == ERANGE)
			fprintf(stderr,
			  "Absolute path maked from '%s' is longer than %d\n",
			  path, PATH_MAX);
		else
			fprintf(stderr, "Absolute path making error: getcwd() error: %s\n",
			  strerror(errno));
		exit(EXIT_FAILURE);
	}
	strcat(p, "/");
	strcat(p, path);
	
	return p;
}

void process_opts(int argc, char **argv)
{
	int c;
	char *syslog_facility = NULL;
	
	
	while ((c = getopt(argc, argv, "vhdfm:l:p:o:s:")) != -1) {
		switch (c) {
		case 'v':
			output_version();
			exit(0);
			break;
		case 'h':
			output_help();
			exit(0);
			break;
		case 'd':
			is_debug_mode = 1;
			break;
		case 'f':
			is_foreground = 1;
			break;
		case 'm':
			dst_file_max_len = atoi(optarg) * 60 * 8000;
			break;
		case 'l':
			syslog_facility = optarg;
			break;
		case 'p':
			pidfile = mk_abs_path(optarg);
			break;
		case 'o':
			dst_dir = mk_abs_path(optarg);
			break;
		case 's':
			script_file = mk_abs_path(optarg);
			break;
		default:
			fprintf(stderr, "Option name or format error\n");
			exit(EXIT_FAILURE);
		}
	}
	
	if (is_foreground)
		is_syslog = 0;
	else
		is_debug_mode = 0;
	
	if (is_syslog) {
		if (syslog_facility)
			open_syslog(syslog_facility);
		else
			open_syslog("user");
	}
	
	if (!dst_dir)
		dst_dir = mk_abs_path(".");
	
	src_file = mk_abs_path(argv[optind]);
	if (!src_file) {
		fprintf(stderr, "DEVICE is not specified\n");
		exit(EXIT_FAILURE);
	}
}

void daemonize(void)
{
	pid_t pid;
	int fd;
	
	
	if (is_foreground)
		return;
	
	umask(0);
	pid = fork();
	if (pid < 0) {
		log_msg(LOG_ERR, "fork() error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else if (pid != 0) {
		exit(EXIT_SUCCESS);
	}
	
	if (setsid() < 0) {
		log_msg(LOG_ERR, "setsid() error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (chdir("/") < 0) {
		log_msg(LOG_ERR, "chdir() error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	if (close(0) < 0) {
		log_msg(LOG_ERR, "closing of 0 descriptor error: %s\n",
		  strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (close(1) < 0) {
		log_msg(LOG_ERR, "closing of 1 descriptor error: %s\n",
		  strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (close(2) < 0) {
		log_msg(LOG_ERR, "closing of 2 descriptor error: %s\n",
		  strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	fd = open("/dev/null", O_RDWR);
	if (fd != 0) {
		if (fd < 0)
			log_msg(LOG_ERR, "/dev/null opening error: %s\n", strerror(errno));
		else
			log_msg(LOG_ERR, "/dev/null opening error: got %d descriptor "
			  "instead of 0\n", fd);
		exit(EXIT_FAILURE);
	}
	fd = dup(0);
	if (fd != 1) {
		if (fd < 0)
			log_msg(LOG_ERR, "dup(0) error: %s\n", strerror(errno));
		else
			log_msg(LOG_ERR, "dup(0) error: got %d descriptor "
			  "instead of 1\n", fd);
		exit(EXIT_FAILURE);
	}
	fd = dup(0);
	if (fd != 2) {
		if (fd < 0)
			log_msg(LOG_ERR, "dup(0) error: %s\n", strerror(errno));
		else
			log_msg(LOG_ERR, "dup(0) error: got %d descriptor "
			  "instead of 2\n", fd);
		exit(EXIT_FAILURE);
	}
}

void mk_pidfile(void)
{
	int fd;
	ssize_t len, cnt;
	char *str = NULL;
	
	
	if (!pidfile)
		return;
	
	fd = open(pidfile, O_WRONLY|O_CREAT|O_EXCL,
	  S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (fd < 0) {
		log_msg(LOG_ERR, "pidfile creation error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	XSTRCATF(&str, 0, "%d", getpid());
	len = strlen(str);
	cnt = write(fd, str, len);
	if (cnt != len) {
		if (cnt < 0)
			log_msg(LOG_ERR, "pidfile writing error: %s\n", strerror(errno));
		else
			log_msg(LOG_ERR, "pidfile is partially written\n");
		exit(EXIT_FAILURE);
	}
	
	XFREE(str);
	if (close(fd) < 0) {
		log_msg(LOG_ERR, "pidfile closing error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void rm_pidfile(void)
{
	if (!pidfile)
		return;
	
	if (unlink(pidfile) < 0)
		log_msg(LOG_ERR, "pidfile removing error: %s\n", strerror(errno));
}

void init(void)
{
	unsigned int i;
	struct sigaction sigact;
	
	
	/*
	 * When we receive some signals, we must call all funtions registered by
	 * atexit().
	 */
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_SIGINFO;
	sigact.sa_sigaction = sighdlr;
	if (sigaction(SIGHUP, &sigact, NULL) == -1) {
		log_msg(LOG_ERR, "sigaction(SIGHUP) error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &sigact, NULL) == -1) {
		log_msg(LOG_ERR, "sigaction(SIGTERM) error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGINT, &sigact, NULL) == -1) {
		log_msg(LOG_ERR, "sigaction(SIGINT) error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGQUIT, &sigact, NULL) == -1) {
		log_msg(LOG_ERR, "sigaction(SIGQUIT) error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGCHLD, &sigact, NULL) == -1) {
		log_msg(LOG_ERR, "sigaction(SIGCHLD) error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	dframe_init(&dataframe);

	for(i = 0; i < LINES_CNT; i++)
		lines[i].fd = -1;
}

void run_script(const char *script_file, const char *fname)
{
	pid_t pid;
	
	
	if (snprintf(dst_file, PATH_MAX, "%s/%s", dst_dir, fname) >= PATH_MAX) {
		log_msg(LOG_ERR, "run_script() error: absolute path maked from "
		  "'%s' and '%s' is longer than %d\n", dst_dir, fname,
		  PATH_MAX);
		exit(EXIT_FAILURE);
	}
	
	pid = fork();
	if (pid < 0) {
		log_msg(LOG_ERR, "run_script() error: fork() error: %s\n",
		  strerror(errno));
		exit(EXIT_FAILURE);
	} else if (pid != 0) {
		return;
	}
	
	if (execl(script_file, script_file, dst_file, NULL) == -1)
		log_msg(LOG_ERR, "run_script() error: execl() erro: %s\n",
		  strerror(errno));
	
	exit(0);
}

int open_src(const char *fname)
{
	int fd;
	struct termios tio;
	
	
	fd = open(fname, O_NOCTTY|O_RDONLY);
	if (fd == -1) {
		log_msg(LOG_ERR, "source open error: %s\n", strerror(errno));
		return -1;
	}
	
	if (!isatty(fd))
		goto ret;
	src_is_tty = 1;
	
	memset(&tio, 0, sizeof(tio));
	
	tio.c_cflag = CS8|CREAD|CLOCAL;
	tio.c_cc[VMIN] = 40;
	tio.c_cc[VTIME] = 0;
	
	cfsetospeed(&tio, B460800);
	cfsetispeed(&tio, B460800);
	
	if (tcsetattr(fd, TCSANOW, &tio) == -1) {
		log_msg(LOG_ERR, "setting serial device parameters error: %s",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	tcflush(fd, TCIOFLUSH);
	
ret:
	return fd;
}

void open_dst(unsigned int n)
{
	time_t t;
	struct tm *tm;
	int ret;


	t = time(NULL);
	if (t == -1) {
		log_msg(LOG_ERR, "time() error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	tm = localtime(&t);
	if (!tm) {
		log_msg(LOG_ERR, "localtime() error\n");
		exit(EXIT_FAILURE);
	}
	ret = snprintf(NULL, 0, "%d.%04d-%02d-%02dT%02d:%02d:%02d",
	  n + 1, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	  tm->tm_hour, tm->tm_min, tm->tm_sec);
	if (ret >= DST_FNAME_LEN) {
		log_msg(LOG_ERR, "destination file name longer than %d\n",
		  DST_FNAME_LEN);
		exit(EXIT_FAILURE);
	}
	sprintf(lines[n].fname, "%d.%04d-%02d-%02dT%02d:%02d:%02d",
	  n + 1, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	  tm->tm_hour, tm->tm_min, tm->tm_sec);

	if ((strlen(dst_dir) + 1 + strlen(lines[n].fname) + 1) > PATH_MAX) {
		log_msg(LOG_ERR, "Absolute path maked from '%s' and '%s' is longer "
		  "than %d\n", dst_dir, lines[n].fname, PATH_MAX);
		exit(EXIT_FAILURE);
	}
	sprintf(dst_file, "%s/%s", dst_dir, lines[n].fname);
	
	lines[n].fd = open(dst_file, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
	if (lines[n].fd == -1) {
		log_msg(LOG_ERR, "open %s err: %s\n", dst_file,
		  strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	lines[n].written_cnt = 0;
}

void close_dst(unsigned int n)
{
	if (lines[n].fd != -1) {
		if (close(lines[n].fd) == -1) {
			log_msg(LOG_ERR, "close %s file error: %s\n", lines[n].fname,
			  strerror(errno));
			exit(EXIT_FAILURE);
		}
		lines[n].fd = -1;
		if (script_file)
			run_script(script_file, lines[n].fname);
	}
}

static ssize_t writen(int fd, const void *buf, size_t count)
{
	size_t nleft = count;
	ssize_t n;
	
	
	while (nleft > 0) {
		n = write(fd, buf, nleft);
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

void save_to_dst(unsigned int n, const char *snd)
{
	ssize_t ret;
	
	
	if (lines[n].fd == -1)
		open_dst(n);

	ret = writen(lines[n].fd, snd, 40);
	if (ret == -1) {
		log_msg(LOG_ERR, "write %s file error: %s\n", lines[n].fname,
		  strerror(errno));
		exit(EXIT_FAILURE);
	}
	lines[n].written_cnt += 40;
	if ((dst_file_max_len) &&
	    (lines[n].written_cnt >= dst_file_max_len))
		close_dst(n);
}

int main(int argc, char **argv)
{
	int fd;
	int n = 0;
	unsigned int i;
	
	process_opts(argc, argv);
	
	daemonize();
	log_msg(LOG_DEBUG, "started\n");
	atexit(_log_stop_msg);
	
	mk_pidfile();
	atexit(rm_pidfile);
	
	init();
	
	do {
		sleep(1);
		fd = open_src(src_file);
		if (fd == -1)
			continue;
		
		while ((n = dframe_read(fd, &dataframe)) > 0) {
			for(i = 0; i < LINES_CNT; i++)
				if (dataframe.lines[i].is_active)
					save_to_dst(i, dataframe.lines[i].snd);
				else
					close_dst(i);
		}
		if (n == -1)
			log_msg(LOG_ERR, "read error: %s\n", strerror(errno));
		close(fd);
	} while (src_is_tty);
	
	return 0;
}
