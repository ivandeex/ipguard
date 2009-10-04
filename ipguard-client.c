/*
 * This program is free software: you can redistribute it and/or modify
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
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "ipguard.h"

static char  ipguard_socket_path[256] = IPGUARD_DEF_SOCKET_PATH;
static int   ipguard_enable = IPGUARD_DEF_ENABLE;
static int   ipguard_debug = IPGUARD_DEF_DEBUG;
static int   ipguard_restrictive = IPGUARD_DEF_RESTRICTIVE;
static int   ipguard_socket = -1;

#if IPGUARD_PTHREADS

#include <pthread.h>

static pthread_mutex_t ipguard_mutex = PTHREAD_MUTEX_INITIALIZER;

#define IPGUARD_MUTEX_LOCK()	pthread_mutex_lock(&ipguard_mutex)
#define IPGUARD_MUTEX_UNLOCK()	pthread_mutex_unlock(&ipguard_mutex)

#else /* IPGUARD_PTHREADS */

#define IPGUARD_MUTEX_LOCK()	do{}while(0)
#define IPGUARD_MUTEX_UNLOCK()	do{}while(0)

#endif /* IPGUARD_PTHREADS */

#define IPGUARD_LOG_PREFIX "ipguard: "

static int
ipguard_log(const char *fmt, ...)
{
	char buf[256] = IPGUARD_LOG_PREFIX;
	int len;
	va_list ap;

	len = sizeof(IPGUARD_LOG_PREFIX) - 1;
	va_start(ap, fmt);
	vsnprintf(buf + len, sizeof(buf) - len - 2, fmt, ap);
	va_end(ap);
	strcat(buf, "\n");
	fputs(buf, stdout);
	fflush(stdout);
	return 0;
}


static int
ipguard_disconnect(void)
{
	if (ipguard_socket >= 0) {
		close(ipguard_socket);
		ipguard_socket = -1;
		if (ipguard_debug)
			ipguard_log("disconnected");
	}
	return 0;
}


static int
ipguard_connect(void)
{
	struct sockaddr_un sa;

	if (ipguard_socket >= 0)
		ipguard_disconnect();

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, ipguard_socket_path,
			(sizeof(struct sockaddr_un) - sizeof(short)));

	ipguard_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipguard_socket < 0) {
		ipguard_log("socket() failed for %s (%s)",
					ipguard_socket_path, strerror(errno));
		return -1;
	}

	if (connect(ipguard_socket, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		ipguard_log("connect() failed for %s (%s)",
					ipguard_socket_path, strerror(errno));
		close(ipguard_socket);
		ipguard_socket = -1;
		return -1;
	}

	if (ipguard_debug)
		ipguard_log("connected to %s", ipguard_socket_path);
	return 0;
}


static int
ipguard_send_query(const char *req, char *reply, int reply_len)
{
	int i, n, k, attempt;
	int len = strlen(req);

	for (attempt = 0; attempt < 1; attempt++) {

		if (ipguard_socket < 0) {
			if (ipguard_connect() < 0) {
				if (ipguard_debug)
					ipguard_log("connection failed");
				return -1;
			}
			attempt++;
		}

		i = 0;
		n = 1;
		while (i < len && n > 0) {
			n = send(ipguard_socket, req + i, len - i, MSG_NOSIGNAL);
			if (n > 0)
				i += n;
			if (ipguard_debug)
				ipguard_log("sent %d bytes out of %d", n, len);
		}

		if (i == len)
			break;

		if (attempt > 0) {
			if (ipguard_debug)
				ipguard_log("cannot send query (%s)", strerror(errno));
			ipguard_disconnect();
			return -1;
		}

		ipguard_disconnect();
	}

	if (ipguard_debug)
		ipguard_log("request sent");

	i = 0;
	n = 1;
	while (i < reply_len - 1 && n > 0) {
		n = recv(ipguard_socket, reply + i, reply_len - i - 1, MSG_NOSIGNAL);
		if (n > 0) {
			for (k = i; k < i + n; k++) {
				if (reply[k] == '\n')
					break;
			}
			i += n;
			if (k != i) {
				i = k;
				break;
			}
		}
		if (ipguard_debug)
			ipguard_log("received %d bytes of response", n);
	}

	reply[i] = '\0';
	if (ipguard_debug)
		ipguard_log("validation response: \"%s\"", reply);

	return 0;
}


int
ipguard_check_ipaddr(const char *ipaddr, char *answer, int answer_len)
{
	int ret, i;
	char req[80], reply[80];

	if (!ipguard_enable) {
		if (answer && answer_len > 0)
			*answer = 0;
		return 0;
	}

	if (ipguard_debug)
		ipguard_log("validate \"%s\"", ipaddr);

	/* leave only one request delimiter, at the end */
	strncpy(req, ipaddr, sizeof(req) - 2);
	for (i = 0; i < sizeof(req) - 2; i++) {
		if (req[i] == '\0' || req[i] == '\n')
			break;
	}
	req[i++] = '\n';
	req[i] = '\0';

	IPGUARD_MUTEX_LOCK();
	ret = ipguard_send_query(req, reply, sizeof(reply) - 1);
	IPGUARD_MUTEX_UNLOCK();

	if (ret < 0) {
		ret = ipguard_restrictive ? 1 : 0;
		strcpy(reply, "FAIL");
	} else if (0 == strcmp(reply, "OK")) {
		ret = 0;
	} else {
		ret = 1;
	}

	if (ipguard_debug) {
		ipguard_log("%s access for \"%s\" (%s)",
					ret == 0? "granted" : "denied", ipaddr, reply);
	}

	if (answer && answer_len > 0)
		strncpy(answer, reply, answer_len);

	return ret;
}


int
ipguard_check_ip(unsigned long ip, char *answer, int answer_len)
{
	char ipaddr[20];

	ip = ntohl(ip);
	sprintf(ipaddr, "%lu.%lu.%lu.%lu",
			(ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, (ip) & 255);

	return ipguard_check_ipaddr(ipaddr, answer, answer_len);
}


int
ipguard_set_debug(int new_debug)
{
	int old_debug = ipguard_debug;
	ipguard_debug = new_debug;
	return old_debug;
}


int
ipguard_set_restrictive(int new_restrictive)
{
	int old_restrictive = ipguard_restrictive;
	ipguard_restrictive = new_restrictive;
	return old_restrictive;
}


int
ipguard_set_enable(int new_enable)
{
	int old_enable = ipguard_enable;
	ipguard_enable = new_enable;
	if (new_enable && ipguard_socket < 0)
		ipguard_connect();
	if (!new_enable && ipguard_socket >= 0)
		ipguard_disconnect();
	return old_enable;
}


int
ipguard_set_socket_path(const char *new_socket_path)
{
	if (NULL == new_socket_path || 0 == *new_socket_path
			|| strlen(new_socket_path) >= sizeof(ipguard_socket_path))
		return -1;
	if (0 == strcmp(ipguard_socket_path, new_socket_path))
		return 0;
	strcpy(ipguard_socket_path, new_socket_path);
	if (ipguard_socket >= 0) {
		ipguard_disconnect();
		ipguard_connect();
	}
	return 0;
}


