/*
 * IP Guard Server
 * Based on MoBlock.c, Morpheus' Blocker
 * Copyright (C) 2004 Morpheus (ebutera at users.berlios.de)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "ipguard-server.h"


/* ================================================== */
/* MAIN DECLARATIONS                                  */
/* ================================================== */

#define DEF_SOCKET_PATH	"/var/run/ipguard.sock"

#define CHECK_INTERVAL	5	/* seconds between checks */

#define MAX_FILE_NAME	256

#define MAX_LISTEN		1024

static FILE *logfile;
static char logfile_name[MAX_FILE_NAME];
static ino_t logfile_ino;
static time_t logfile_lastcheck;
static int log2syslog;
static int log2file;
static int log2stderr;
static int log2stdout;

static char pidfile_name[MAX_FILE_NAME];

#define LIST_DAT 1
#define LIST_PG1 2
#define LIST_PG2 3

static int blocklist_type;
static char blocklist_filename[MAX_FILE_NAME];
static time_t blocklist_mtime;

static pthread_rwlock_t blocklist_lock;

static int merged_ranges;
static int skipped_ranges;
static int initialized;

static int srv_sock = -1;
static char socket_path[MAX_FILE_NAME] = DEF_SOCKET_PATH;

int verbose;
int log_allowed;

static pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
static int count_threads;

void reopen_logfile(void);


/* ================================================== */
/* SEARCH                                             */
/* ================================================== */

int
blocking_ipaddr_blocked(const char *ipaddr, char *answer, int answer_len)
{
	recType rec;
	struct in_addr in;
	unsigned long ip;
	int ret;

	if (NULL == ipaddr || 0 == *ipaddr) {
		if (answer && answer_len > 0)
			strncpy(answer, "NULL ADDR", answer_len);
		return -1;
	}

	if (0 == inet_aton(ipaddr, &in)) {
		if (answer && answer_len > 0)
			strncpy(answer, "NOT IP ADDRESS", answer_len);
		return -1;
	}

	pthread_rwlock_rdlock(&blocklist_lock);
	if (initialized) {
		ip = in.s_addr;
		ip = ntohl(ip);
		ret = rbt_find(ip, &rec);
		pthread_rwlock_unlock(&blocklist_lock);
	} else {
		pthread_rwlock_unlock(&blocklist_lock);
		if (answer && answer_len > 0)
			strncpy(answer, "NO GUARD FILE", answer_len);
		if (verbose)
			log_action("no guard file");
		return -1;
	}

	if (ret == STATUS_OK) {
		log_action("blocked: %s, hits: %d, SRC: %s",
					rec.blockname, rec.hits, ipaddr);
		if (answer && answer_len > 0)
			strncpy(answer, rec.blockname, answer_len);
		return 1;
	}

	if (verbose || log_allowed)
		log_action("allowed: %s", ipaddr);
	if (answer && answer_len > 0)
		strncpy(answer, "OK", answer_len);
	return 0;
}


/* ================================================== */
/* LOGGING                                            */
/* ================================================== */


int
check_time(time_t *lastp)
{
	time_t now = time(NULL);
	if (*lastp == 0 || now - *lastp > CHECK_INTERVAL) {
		*lastp = now;
		return 1;
	}
	return 0;
}


int
log_action(const char *fmt, ...)
{
	va_list ap;
	time_t tv;
	char msg[256], time_buf[32];
	struct stat st;

	time(&tv);
	*time_buf = '\0';
	strncpy(msg, ctime_r(&tv, time_buf), 19);
	msg[19] = '|';
	msg[20] = ' ';

	va_start(ap, fmt);
	vsnprintf(msg + 21, sizeof(msg) - 22 - 2, fmt, ap);
	va_end(ap);
	msg[sizeof(msg) - 3] = 0;
	strcat(msg, "\n");

	if (log2file) {
		if (check_time(&logfile_lastcheck)) {
			if (stat(logfile_name, &st) != 0 || st.st_ino != logfile_ino)
				reopen_logfile();
		}
		fputs(msg, logfile);
		fflush(logfile);
	}
	if (log2stdout) {
		fputs(msg, stdout);
		fflush(stdout);
	}
	if (log2stderr)
		fputs(msg, stderr);
	if (log2syslog)
		syslog(LOG_INFO, msg + 21);
	return 0;
}


int
blocking_openlog(const char *filename)
{
	struct stat st;
	if (logfile != NULL)
		fclose(logfile);
	logfile = NULL;
	log2file = log2syslog = log2stderr = log2stdout = 0;
	*logfile_name = 0;
	logfile_lastcheck = 0;
	logfile_ino = 0;
	if (0 == strcasecmp(filename, "syslog")) {
		log2syslog = 1;
		return 0;
	}
	if (0 == strcasecmp(filename, "stderr")) {
		log2stderr = 1;
		return 0;
	}
	if (0 == strcasecmp(filename, "stdout")) {
		log2stdout = 1;
		return 0;
	}
	if (strlen(filename) >= sizeof(logfile_name)) {
		log2stderr = 1;
		log_action("log file name too long!");
		return -1;
	}
	strncpy(logfile_name, filename, sizeof(logfile_name));
	logfile = fopen(filename, "a");
	if (logfile == NULL) {
		log2stderr = 1;
		log_action("cannot open logfile %s", filename);
		return -1;
	}
	if (stat(filename, &st) == 0)
		logfile_ino = st.st_ino;
	log2file = 1;
	return 0;
}


void
reopen_logfile(void)
{
	if (logfile != NULL) {
		fclose(logfile);
		logfile = NULL;
	}
	if (*logfile_name) {
		log2syslog = 0;
		logfile = fopen(logfile_name, "a");
		if (logfile == NULL) {
			log2syslog = 1;
			log_action("cannot open log file %s", logfile_name);
		}
	}
	log_action("reopened log file");
}


/* ================================================== */
/* LOADING LISTS                                      */
/* ================================================== */

static inline void
ranged_insert(char *name,char *ipmin,char *ipmax)
{
	recType tmprec;
	int ret;

	if ( strlen(name) > (BNAME_LEN-1) ) {
		strncpy(tmprec.blockname, name, BNAME_LEN);
		tmprec.blockname[BNAME_LEN-1]='\0';	
	}
	else {
		strcpy(tmprec.blockname,name);
	}
	tmprec.ipmax = ntohl(inet_addr(ipmax));
	tmprec.hits = 0;
	ret = rbt_insert(ntohl(inet_addr(ipmin)), &tmprec);
	if (ret != STATUS_OK) {
		switch(ret) {
			case STATUS_MEM_EXHAUSTED:
				log_action("error inserting range, memory exchausted");
				break;
			case STATUS_DUPLICATE_KEY:
				log_action("duplicate range ( %s )", name);
				break;
			case STATUS_MERGED:
				merged_ranges++;
				break;
			case STATUS_SKIPPED:
				skipped_ranges++;
				break;
			default:
				log_action("unexpected return value %d from ranged_insert()", ret);
				break;
		}
	}
}


int
loadlist_pg1(const char* filename)
{
	FILE *fp;
	ssize_t count;
	char *line = NULL;
	size_t len = 0;
	int ntot = 0;
	char c, *p;
	int i;
	char *start, *end;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		log_action("error opening %s, aborting", filename);
		return -1;
	}

	while ((count = getline(&line, &len, fp)) != -1) {

		if (*line == '#')	/* comment line, skip */
			continue;

		for (p = line + count - 1; p != line; p--) {
			c = *p;
			if (c == '\r' || c == '\n' || c == ' ')
				*p = '\0';
			else
				break;
		}

		if (*line == '\0')	/* empty line, skip */
			continue;

		while (p != line) {
			c = *p;
			if (c != '.' && (c < '0' || c > '9'))
				break;
			p--;
		}
		if ((c != '-' && c != ':') || p == line) {
			log_action(".p2p line \"%s\" misses '-', skip", line);
			continue;
		}

		if (c == ':') {
			*p = '\0';
			start = end = p + 1;
		}
		else {
			end = p + 1;
			*p-- = '\0';
			while (p != line) {
				c = *p;
				if (c != '.' && (c < '0' || c > '9'))
					break;
				p--;
			}
			if (c != ':' || p == line) {
				log_action(".p2p line \"%s\" misses '-', skip", line);
				continue;
			}
			*p = '\0';
			start = p + 1;
		}

		ranged_insert(line, start, end);
		ntot++;
	}

	if (line)
		free(line);
	fclose(fp);
	log_action("* ranges loaded: %d", ntot);
	return 0;
}


int
loadlist_pg2(const char *filename)		/* supports only v2 files */
{
	FILE *fp;
	int i, j, c, retval = 0, ntot = 0;
	char name[100], ipmin[16];	/* hope we don't have a list with longer names.. */
	uint32_t start_ip, end_ip;
	struct in_addr startaddr,endaddr;
	size_t s;

	fp = fopen(filename,"r");
	if (fp == NULL) {
		log_action("error opening %s, aborting...", filename);
		return -1;
	}

	for (j = 0; j < 4; j++) {
		c = fgetc(fp);
		if (c != 0xff) {
			log_action("byte %d: 0x%x != 0xff, aborting...", j+1, c);
			fclose(fp);
			return -1;
		}
	}

	c = fgetc(fp);
	if (c != 'P') {
		log_action("byte 5: %c != P, aborting...", c);
		fclose(fp);
		return -1;
	}

	c = fgetc(fp);
	if (c != '2') {
		log_action("byte 6: %c != 2, aborting...", c);
		fclose(fp);
		return -1;
	}

	c = fgetc(fp);
	if (c != 'B') {
		log_action("byte 7: %c != B, aborting...", c);
		fclose(fp);
		return -1;
	}

	c = fgetc(fp);
	if (c != 0x02) {
		log_action("byte 8: version: %d != 2, aborting...", c);
		fclose(fp);
		return -1;
	}

	do {
		i = 0;
		do {
			name[i] = fgetc(fp);
			i++;
		} while (name[i-1] != 0x00 && name[i-1] != EOF);
		if (name[i-1] != EOF) {
			name[i-1] = '\0';
			s = fread(&start_ip, 4, 1, fp);
			if ( s != 1 ) {
				log_action("failed to read start IP: %d != 1, aborting...", (int)s);
				fclose(fp);
				return -1;
			}
			s = fread(&end_ip, 4, 1, fp);
			if (s != 1) {
				log_action("failed to read end IP: %d != 1, aborting...", (int)s);
				fclose(fp);
				return -1;
			}

			startaddr.s_addr = start_ip;
			endaddr.s_addr = end_ip;
			strcpy(ipmin, inet_ntoa(startaddr));
			ranged_insert(name, ipmin, inet_ntoa(endaddr));
			ntot++;
		}
		else {
			retval = EOF;
		}
	} while (retval != EOF);
	fclose(fp);
	log_action("* ranges loaded: %d",ntot);
	return 0;
}


int
loadlist_dat(const char *filename)
{
	FILE *fp;
	int ntot = 0;
	char readbuf[200], *name, start_ip[16], end_ip[16];
	unsigned short ip1_0, ip1_1, ip1_2, ip1_3, ip2_0, ip2_1, ip2_2, ip2_3;
    
	fp = fopen(filename, "r");
	if (fp == NULL) {
		log_action("error opening %s, aborting...", filename);
		return -1;
	}

	while (fgets(readbuf,200,fp) != NULL) {
		if ( readbuf[0] == '#')
			continue;		/* comment line, skip */
		sscanf(readbuf, "%hu.%hu.%hu.%hu - %hu.%hu.%hu.%hu ,",
				&ip1_0, &ip1_1, &ip1_2, &ip1_3,
				&ip2_0, &ip2_1, &ip2_2, &ip2_3);
		name = readbuf+42;
		name[strlen(name)-2] = '\0';	/* strip ending \r\n */
		sprintf(start_ip,"%d.%d.%d.%d", ip1_0, ip1_1, ip1_2, ip1_3);
		sprintf(end_ip,"%d.%d.%d.%d", ip2_0, ip2_1, ip2_2, ip2_3);
		ranged_insert(name, start_ip, end_ip);
		ntot++;
	}
	fclose(fp);
	log_action("* ranges loaded: %d", ntot);
	return 0;
}


int
blocking_reload_list(void)
{
	int ret;
	struct stat st;

	destroy_tree();		/* clear loaded ranges */
	blocklist_mtime = 0;
	initialized = 0;

	switch (blocklist_type) {
		case LIST_DAT:
			if (verbose)
				log_action("loading dat %s", blocklist_filename);
			ret = loadlist_dat(blocklist_filename);
			break;
		case LIST_PG1:
			if (verbose)
				log_action("loading p2p %s", blocklist_filename);
			ret = loadlist_pg1(blocklist_filename);
			break;
		case LIST_PG2:
			if (verbose)
				log_action("loading pg2 %s", blocklist_filename);
			ret = loadlist_pg2(blocklist_filename);
			break;
		default:
			log_action("unknown blocklist type while reloading list");
			ret = -1;
			break;
	}

	if (ret == 0) {
		if (stat(blocklist_filename, &st) == 0) {
			blocklist_mtime = st.st_mtime;
		}
		log_action("* merged ranges: %d", merged_ranges);
		log_action("* skipped useless ranges: %d", skipped_ranges);
		initialized = 1;
	}

	return ret;
}


int
blocking_openlist(char list_type, const char *list_file)
{
	if (NULL == list_file || '\0' == *list_file
			|| strlen(list_file) >= sizeof(blocklist_filename) - 1) {
		log_action("incorrect list file name");
		return -1;
	}

	blocklist_type = 0;
	strcpy(blocklist_filename, list_file);

	switch (list_type) {
		case 'd':			/* ipfilter.dat file format */
			blocklist_type = LIST_DAT;
			break;
		case 'n':			/* peerguardian 2.x file format .p2b */
			blocklist_type = LIST_PG2;
			break;
		case 'p':			/* peerguardian file format .p2p */
			blocklist_type = LIST_PG1;
			break;
		default:
			log_action("unknown block list type '%c'", list_type);
			return -1;
	}

	return 0;
}


/* ================================================== */
/* SERVER                                             */
/* ================================================== */


int
set_socket_path(const char *new_sock_path)
{
	struct sockaddr_un sa;
	if (NULL == new_sock_path || '\0' == *new_sock_path
			|| strlen(new_sock_path) >= sizeof(sa) - sizeof(sa.sun_family)
			|| strlen(new_sock_path) >= sizeof(socket_path)) {
		log_action("incorrect socket path");
		return -1;
	}

	strcpy(socket_path, new_sock_path);
	return 0;
}


int
socket_close(void)
{
	if (srv_sock >= 0) {
		close(srv_sock);
		srv_sock = -1;
		unlink(socket_path);
	}
	return 0;
}


int
socket_server_init(void)
{
	struct sockaddr_un sa;

	socket_close();

	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, socket_path);

	srv_sock = socket( AF_UNIX, SOCK_STREAM, 0);
	if (srv_sock < 0) {
		log_action("socket() failed (%s)", strerror(errno));
		return -1;
	}

	if (bind(srv_sock, &sa, sizeof(sa)) < 0) {
		log_action("bind() to %s failed (%s)", socket_path, strerror(errno));
		return -1;
	}

	if (listen(srv_sock, MAX_LISTEN) < 0) {
		log_action("listen() failed (%s)", strerror(errno));
		return -1;
	}

	if (chmod(socket_path, 0777) < 0) {
		log_action("chmod() of %s failed (%s)", socket_path, strerror(errno));
		return -1;
	}

	return 0;
}


int
handle_request(int cli_sock, char *buf, int buf_len, int *off_ptr)
{
	int i, k, j, n, len;
	char reply[80];
	int ret = 0;
	int off = *off_ptr;
    fd_set fds;
    struct timeval tv;
    int sel;

	k = off;
	for (i = 0; i < k; i++) {
		if (buf[i] == '\n')
			break;
	}

	if (i == k) {
		n = 1;
		while (k < buf_len - 1 && n > 0) {
            FD_ZERO(&fds);
            FD_SET(cli_sock, &fds);

            tv.tv_sec = CLIENT_TIMEOUT;
            tv.tv_usec = 0;

            sel = select(cli_sock + 1, &fds, NULL, NULL, &tv);
            if (sel == -1) {
                log_action("recv from %d select error %d", cli_sock, errno);
                return -1;
            }
            if (!sel) {
                if (verbose)
                    log_action("recv socket %d timeout", cli_sock);
                return -1;
            }

			n = recv(cli_sock, buf + k, buf_len - k - 1, MSG_NOSIGNAL);
			if (n < 0)
				ret = -1;
			if (n > 0) {
				for (i = k; i < k + n; i++) {
					if (buf[i] == '\n')
						break;
				}
				k += n;
				if (i != k)
					break;
			}
		}
		if (verbose)
			log_action("received %d bytes (%d to handle) from %d",
			            k - off, i - off, cli_sock);
	}

	if (i == off)
		return -1;

	buf[i] = '\0';
	if (verbose) {
		if (i < off)
			log_action("picked %d bytes out of %d (%s) from %d",
			            i, off, buf, cli_sock);
		else
			log_action("pulled %d bytes starting at %d (%s) from %d",
			            i - off, off, buf, cli_sock);
	}

	blocking_ipaddr_blocked(buf, reply, sizeof(reply) - 1);

	len = strlen(reply);
	reply[len++] = '\n';
	reply[len] = '\0';

	j = 0;
	n = 1;
	while (j < len && n > 0) {
        FD_ZERO(&fds);
        FD_SET(cli_sock, &fds);

        tv.tv_sec = CLIENT_TIMEOUT;
        tv.tv_usec = 0;

        sel = select(cli_sock + 1, NULL, &fds, NULL, &tv);
        if (sel == -1) {
            log_action("send to %d select error %d", cli_sock, errno);
            return -1;
        }
        if (!sel) {
            if (verbose)
                log_action("send socket %d timeout", cli_sock);
            return -1;
        }

		n = send(cli_sock, reply + j, len - j, MSG_NOSIGNAL);
		if (n > 0)
			j += n;
	}

	if (j < len)
		ret = -1;

	if (verbose) {
		reply[len - 1] = '\0';
		log_action("sent %d bytes of \"%s\" to %d", len, reply, cli_sock);
	}

	i++;
	off = k - i;
	if (off > 0) {
		memcpy(buf, buf + i, off);
		buf[off] = '\0';
		if (verbose)
			log_action("buffer off=%d rest=\"%s\" for %d", off, buf, cli_sock);
	} else {
		off = 0;
	}
	*off_ptr = off;

	return ret;
}


void *
client_thread (void *arg)
{
	int cli_sock = (int) arg;
	char buf[80];
	int off = 0;
	int ret = 0;
    int count;

    pthread_mutex_lock(&count_mutex);
    count = ++count_threads;
    pthread_mutex_unlock(&count_mutex);

	if (verbose)
		log_action("spawn thread %d for socket %d", count, cli_sock);
	while (ret == 0)
		ret = handle_request(cli_sock, buf, sizeof(buf) - 1, &off);

	if (verbose)
		log_action("disconnect client socket %d", cli_sock);
	shutdown(cli_sock, SHUT_RDWR);
	close(cli_sock);

    pthread_mutex_lock(&count_mutex);
    --count_threads;
    pthread_mutex_unlock(&count_mutex);

	pthread_exit(arg);
	return arg;
}


int
socket_server_loop(void)
{
	int cli_sock;
	unsigned int salen;
	struct sockaddr_un sa;
	int ret;
	pthread_t thread;
	char buf[80];
	int off;

	if (verbose)
		log_action("listening on %s", socket_path);

	while (1) {
		salen = sizeof(sa);
		cli_sock = accept(srv_sock, &sa, &salen);
		if (cli_sock < 0) {
			if (errno == EINTR)
				continue;
			log_action("accept() failed (%s)", strerror(errno));
			return 0;
		}
		ret = pthread_create(&thread, NULL, client_thread, (void *)cli_sock);
		if (ret != 0) {
			log_action("pthread_create() failed: %s", strerror(ret));
			off = 0;
			handle_request(cli_sock, buf, sizeof(buf) - 1, &off);
        	shutdown(cli_sock, SHUT_RDWR);
			close(cli_sock);
		}
		pthread_detach(thread); /* to automatically reclaim memory upon exit */
	}
}


void *
list_reload_thread(void * arg)
{
	struct stat st;
	struct timeval tv;
	while(1) {
		tv.tv_sec = CHECK_INTERVAL;
		tv.tv_usec = 0;
		select(0, NULL, NULL, NULL, &tv);
		if (verbose)
			log_action("next list check...");
		if (0 == blocklist_type
				|| stat(blocklist_filename, &st) < 0
				|| blocklist_mtime == st.st_mtime)
			continue;
		log_action("block list was updated. reloading");
		pthread_rwlock_wrlock(&blocklist_lock);
		blocking_reload_list();
		pthread_rwlock_unlock(&blocklist_lock);
	}
	return arg;
}


/* ================================================== */
/* SIGNAL HANDLING                                    */
/* ================================================== */

void
ipguard_sa_handler(int sig)
{
	switch (sig) {
		case SIGUSR1:
		log_action("Got SIGUSR1! Dumping stats...");
		ll_show();
		reopen_logfile();
		break;
	case SIGUSR2:
		log_action("Got SIGUSR2! Dumping stats to /var/log/MoBlock.stats");
		ll_log();
		break;
	case SIGHUP:
		log_action("Got SIGHUP! Dumping and resetting stats, reloading blocklist");
		ll_log();
		ll_clear();		/* clear stats list */
		blocking_reload_list();
		reopen_logfile();
		break;
	case SIGTERM:
		log_action("Got SIGTERM! Dumping stats and exiting.");
		ll_log();
		exit(0);
	case SIGINT:
		socket_close();
		exit(0);
	default:
		log_action("Received signal = %d but not handled", sig);
		break;
	}
}


int
blocking_sigactions(void)
{
    struct sigaction my_sa;
    
	my_sa.sa_handler = ipguard_sa_handler;
	my_sa.sa_flags = SA_RESTART;
    
	if (sigaction(SIGUSR1, &my_sa, NULL) < 0) {
		log_action("error setting signal handler for SIGUSR1");
		return -1;
	}
	if (sigaction(SIGUSR2, &my_sa, NULL) < 0) {
		log_action("error setting signal handler for SIGUSR2");
		return -1;
	}
	if (sigaction(SIGHUP, &my_sa, NULL) < 0) {
		log_action("error setting signal handler for SIGHUP");
		return -1;
	}
	if (sigaction(SIGTERM, &my_sa, NULL) < 0) {
		log_action("error setting signal handler for SIGTERM");
		return -1;
	}
	if (sigaction(SIGINT, &my_sa, NULL) < 0) {
		log_action("error setting signal handler for SIGINT");
		return -1;
	}
	return 0;
}


/* ================================================== */
/* MAIN                                               */
/* ================================================== */


void
on_quit()
{
	socket_close();
	if (*pidfile_name) {
		unlink(pidfile_name);
		*pidfile_name = '\0';
	}
}


int
set_pid_file(const char *filename)
{
	if (NULL == filename || 0 == *filename
			|| strlen(filename) >= sizeof(pidfile_name)) {
		log_action("incorrect pid file name");
	}

	if (access(filename, F_OK) == 0) {
		log_action("pid file %s exists - terminating", filename);
		return -1;
	}

	strcpy(pidfile_name, filename);
	return 0;
}


int
create_pid_file(void)
{
	FILE *pid_file;
	pid_t pid = getpid();

	pid_file = fopen(pidfile_name, "w");
	if (pid_file == NULL) {
		log_action("cannot create pid file %s (%s)", pidfile_name, strerror(errno));
		return -1;
	}

	fprintf(pid_file, "%d\n", (int)pid);
	fclose(pid_file);
	return 0;
}


void
print_options(void)
{
	printf("syntax: ipguard -dnp <blocklist> [ -v ] [ -a ] [ -D ] "
			"[ -S <socketpath> ] [ -P <pidfile> ] [ -L <logfile> ]\n\n");
	printf("\t-d\tblocklist is an ipfilter.dat file\n");
	printf("\t-n\tblocklist is a peerguardian 2.x file (.p2b)\n");
	printf("\t-p\tblocklist is a peerguardian file (.p2p)\n");
	printf("\t-S\tset socket path\n");
	printf("\t-L\tlog to given file or \"stdout\" or \"syslog\"\n");
	printf("\t-D\tdaemonize\n");
	printf("\t-P\tcreate pidfile\n");
	printf("\t-a\tlog allowed addresses\n");
	printf("\t-v\tbe verbose\n");
}


int
main (int argc, char **argv)
{
	int ret;
	char *logfile = NULL;
	int daemonize = 0;
	pid_t pid;
	pthread_t list_thread;

	log2stderr = 1;
	if (pthread_rwlock_init(&blocklist_lock, NULL)) {
		log_action("cannot init blockilist lock");
		exit(1);
	}
	atexit(on_quit);

	while (1) {
		ret = getopt(argc, argv, "d:n:p:S:L:P:Dav");
		if (ret == -1)
			break;
		switch (ret) {
			case 'd':		/* ipfilter.dat file format */
			case 'n':		/* peerguardian 2.x file format .p2b */
			case 'p':		/* peerguardian file format .p2p */
				blocking_openlist(ret, optarg);
				break;
			case 'S':
				if (set_socket_path(optarg) < 0)
					exit(1);
				break;
			case 'L':
				logfile = optarg;
				break;
			case 'P':
				if (set_pid_file(optarg) < 0)
					exit(1);
				break;
			case 'D':
				daemonize = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'a':
				log_allowed = 1;
				break;
			default:
				print_options();
				exit(1);
				break;
		}
	}

	if (!daemonize) {
		blocking_reload_list();
		if (!initialized) {
			log_action("no blocklist loaded");
			exit(1);
		}
	}

	if (blocking_sigactions() < 0)
		exit(1);

	if (socket_server_init() < 0)
		exit(1);

	if (logfile && blocking_openlog(logfile) < 0)
		exit(1);

	if (daemonize) {
		pid = fork();
		if (pid == -1) {
			log_action("fork() failed");
			exit(1);
		}
		if (pid != 0) {
			/* do not remove */
			*socket_path = *pidfile_name = '\0';
			exit(0);
		}
		setsid();
	}

	if (*pidfile_name && create_pid_file() < 0)
		exit(1);

	if (daemonize)
		blocking_reload_list();

	if (pthread_create(&list_thread, NULL, list_reload_thread, NULL)) {
		log_action("cannot create list reload thread");
		exit(1);
	}

	while (1) {
		if (socket_server_loop() < 0)
			exit(1);
		socket_close();
		if (socket_server_init() < 0)
			exit(1);
	}

	return 0;
}

