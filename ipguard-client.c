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


#define IPGUARD_CURSES 0

#if IPGUARD_CURSES
#define IPGUARD_CURSES_PREFIX "\r"
#else
#define IPGUARD_CURSES_PREFIX
#endif /* IPGUARD_CURSES */


static ipguard_cfg_t ipguard_common_cfg;


static ipguard_cfg_t *
ipguard_get_common_cfg(void)
{
	ipguard_cfg_t *cfg = &ipguard_common_cfg;
	if (! *cfg->socket_path)
		ipguard_init(cfg);
	return cfg;
}


static int
ipguard_log(ipguard_cfg_t *cfg, const char *fmt, ...)
{
	char buf[256] = IPGUARD_CURSES_PREFIX IPGUARD_LOG_PREFIX;
	int len;
	va_list ap;

	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	len = strlen(buf);
	va_start(ap, fmt);
	vsnprintf(buf + len, sizeof(buf) - len - 2, fmt, ap);
	va_end(ap);

#if defined(IPGUARD_APACHE_MODULE)
  #ifndef MODULE_LOG_LEVEL
  #define MODULE_LOG_LEVEL APLOG_NOTICE
  #endif
	if (cfg->req)
		ap_log_rerror(APLOG_MARK, MODULE_LOG_LEVEL, 0, cfg->req, "%s", buf);
#elif defined(IPGUARD_NGINX_MODULE)
    if (cfg->req)
        ipguard_ngx_log(cfg->req->connection->log, MODULE_LOG_LEVEL, "%s", buf);
#else  /* !IPGUARD_APACHE_MODULE && !IPGUARD_NGINX_MODULE */
  #if IPGUARD_CURSES
	strcat(buf, "\r");
  #endif
	strcat(buf, "\n");
	fputs(buf, stdout);
	fflush(stdout);
#endif /* IPGUARD_APACHE_MODULE */

	return 0;
}


static int
ipguard_disconnect(ipguard_cfg_t *cfg)
{
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	if (cfg->socket >= 0) {
    	shutdown(cfg->socket, SHUT_RDWR);
		close(cfg->socket);
		cfg->socket = -1;
		if (cfg->debug)
			ipguard_log(cfg, "disconnected");
	}

	return 0;
}


static int
ipguard_connect(ipguard_cfg_t *cfg)
{
	struct sockaddr_un sa;
	char erbuf[80];

	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	if (cfg->socket >= 0)
		ipguard_disconnect(cfg);

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, cfg->socket_path, sizeof(sa) - sizeof(sa.sun_family));

	cfg->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfg->socket < 0) {
		ipguard_log(cfg, "socket() failed for %s (%s)",
					cfg->socket_path, strerror_r(errno, erbuf, sizeof(erbuf)));
		return -1;
	}

	if (connect(cfg->socket, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		ipguard_log(cfg, "connect() failed for %s (%s)",
					cfg->socket_path, strerror_r(errno, erbuf, sizeof(erbuf)));
		close(cfg->socket);
		cfg->socket = -1;
		return -1;
	}

	if (cfg->debug)
		ipguard_log(cfg, "connected to %s", cfg->socket_path);
	return 0;
}


static int
ipguard_send_query(ipguard_cfg_t *cfg, const char *req, char *reply, int reply_len)
{
	int i, n, k, attempt;
	char erbuf[80];
	int len = strlen(req);
	fd_set fds;
	struct timeval tv0;
	int sel;

	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	for (attempt = 0; attempt < 2; attempt++) {

		if (cfg->socket < 0) {
			if (ipguard_connect(cfg) < 0) {
				if (cfg->debug)
					ipguard_log(cfg, "connection failed");
				return -1;
			}
			attempt++;
		}

        tv0.tv_sec = cfg->timeout;
        tv0.tv_usec = 0;
		i = 0;
		n = 1;

		while (i < len && (n > 0 || (n < 0 && errno == EINTR))) {
            struct timeval tv = tv0;
            FD_ZERO(&fds);
            FD_SET(cfg->socket, &fds);

            sel = select(cfg->socket + 1, NULL, &fds, NULL, &tv);
            if (sel == -1) {
                if (errno == EINTR) {
                    if (cfg->debug)
                        ipguard_log(cfg, "recv select caught eintr, sec=%d",
                                    (int) tv.tv_sec);
                    tv0 = tv;   /* use remaining time */
                    continue;
                }
                if (cfg->debug)
                    ipguard_log(cfg, "ipguard send select error %d", errno);
                break;
            }
            if (!sel) {
                if (cfg->debug)
                    ipguard_log(cfg, "ipguard send timeout");
                break;
            }
            tv0.tv_sec = cfg->timeout;    /* reload timeout */
            tv0.tv_usec = 0;

			n = send(cfg->socket, req + i, len - i, MSG_NOSIGNAL);
			if (n > 0)
				i += n;
			if (cfg->debug)
				ipguard_log(cfg, "sent %d bytes out of %d, errno=%d", n, len, errno);
		}

		if (i == len)
			break;

		if (attempt > 0) {
			if (cfg->debug)
				ipguard_log(cfg, "cannot send query (%s)",
	    					strerror_r(errno, erbuf, sizeof(erbuf)));
			return -1;
		}

		ipguard_disconnect(cfg);
	}

	if (cfg->debug)
		ipguard_log(cfg, "request sent");

    tv0.tv_sec = cfg->timeout;
    tv0.tv_usec = 0;
	i = 0;
	n = 1;

	while (i < reply_len - 1 && (n > 0 || (n < 0 && errno == EINTR))) {
        struct timeval tv = tv0;
        FD_ZERO(&fds);
        FD_SET(cfg->socket, &fds);

        sel = select(cfg->socket + 1, &fds, NULL, NULL, &tv);
        if (sel == -1) {
            if (errno == EINTR) {
                if (cfg->debug)
                    ipguard_log(cfg, "send select caught eintr, sec=%d",
                                (int) tv.tv_sec);
                tv0 = tv;   /* use remaining time */
                continue;
            }
            if (cfg->debug)
                ipguard_log(cfg, "ipguard recv select error %d", errno);
            return -1;
        }
        if (!sel) {
            if (cfg->debug)
                ipguard_log(cfg, "ipguard recv timeout");
            return -1;
        }
        tv0.tv_sec = cfg->timeout;    /* reload timeout */
        tv0.tv_usec = 0;

		n = recv(cfg->socket, reply + i, reply_len - i - 1, MSG_NOSIGNAL);
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
		if (cfg->debug)
			ipguard_log(cfg, "received %d bytes of response, errno=%d", n, errno);
	}

	reply[i] = '\0';
	if (cfg->debug)
		ipguard_log(cfg, "validation response: \"%s\"", reply);

	return 0;
}


MODULE_INTERNAL int
ipguard_check_ipaddr(ipguard_cfg_t *cfg, const char *ipaddr, char *answer, int answer_len)
{
	int ret, i;
	char req[80], reply[80];

	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	if (!cfg->enable) {
		if (answer && answer_len > 0)
			*answer = 0;
		return 0;
	}

	if (cfg->debug)
		ipguard_log(cfg, "validate \"%s\"", ipaddr);

	/* leave only one request delimiter, at the end */
	strncpy(req, ipaddr, sizeof(req) - 2);
	for (i = 0; i < (int)sizeof(req) - 2; i++) {
		if (req[i] == '\0' || req[i] == '\n')
			break;
	}
	req[i++] = '\n';
	req[i] = '\0';

	if (0 == strcmp(req, "::1\n")) {
		if (answer && answer_len > 0)
			strncpy(answer, "OK", answer_len);
		return 0;
	}

	ipguard_mutex_lock(cfg);
	ret = ipguard_send_query(cfg, req, reply, sizeof(reply) - 1);
	if (ret < 0 || !IPGUARD_KEEPALIVE)
	    ipguard_disconnect(cfg);
	ipguard_mutex_unlock(cfg);

	if (ret < 0) {
		ret = cfg->restrictive ? 1 : 0;
		strcpy(reply, "FAIL");
	} else {
	    ret = (0 == strcmp(reply, "OK") ? 0 : 1);
	}

	if (cfg->debug) {
		ipguard_log(cfg, "%s access for \"%s\" (%s)",
					ret == 0? "granted" : "denied", ipaddr, reply);
	}

	if (answer && answer_len > 0)
		strncpy(answer, reply, answer_len);

	return ret;
}


#if !defined(IPGUARD_APACHE_MODULE)
MODULE_INTERNAL int
ipguard_check_ip(ipguard_cfg_t *cfg, unsigned long ip, char *answer, int answer_len)
{
	char ipaddr[20];

	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	ip = ntohl(ip);
	sprintf(ipaddr, "%lu.%lu.%lu.%lu",
			(ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, (ip) & 255);

	return ipguard_check_ipaddr(cfg, ipaddr, answer, answer_len);
}
#endif /* !IPGUARD_APACHE_MODULE */


#if !defined(IPGUARD_APACHE_MODULE)
MODULE_INTERNAL int
ipguard_check_sockaddr (ipguard_cfg_t *cfg, void *sockaddr_ptr, char *answer, int answer_len)
{
	struct sockaddr_in *sin_ptr = (struct sockaddr_in *) sockaddr_ptr;

	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	if (NULL == sin_ptr) {
		if (answer && answer_len > 0)
			strncpy(answer, "NULL", answer_len);
		if (cfg->debug)
			ipguard_log(cfg, "sockaddr_ptr is null");
		return -1;
	}
	if (sin_ptr->sin_family != AF_INET) {
		if (answer && answer_len > 0)
			strncpy(answer, "NOT AF_INET", answer_len);
		if (cfg->debug)
			ipguard_log(cfg, "sockaddr_ptr is not AF_INET");
		return -1;
	}
	return ipguard_check_ip(cfg, sin_ptr->sin_addr.s_addr, answer, answer_len);
}
#endif /* !IPGUARD_APACHE_MODULE */


MODULE_INTERNAL int
ipguard_set_debug(ipguard_cfg_t *cfg, int new_debug)
{
	int old_debug;
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	old_debug = cfg->debug;
	if (new_debug != -1)
		cfg->debug = !!new_debug;
	return old_debug;
}


MODULE_INTERNAL int
ipguard_set_restrictive(ipguard_cfg_t *cfg, int new_restrictive)
{
	int old_restrictive;
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	old_restrictive = cfg->restrictive;
	if (new_restrictive != -1)
		cfg->restrictive = new_restrictive;
	return old_restrictive;
}

#if !defined(IPGUARD_APACHE_MODULE)
MODULE_INTERNAL int
ipguard_set_timeout(ipguard_cfg_t *cfg, int new_timeout)
{
	int old_timeout;
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	old_timeout = cfg->timeout;
	if (new_timeout > 0)
		cfg->timeout = new_timeout;
	return old_timeout;
}
#endif

MODULE_INTERNAL int
ipguard_set_enable(ipguard_cfg_t *cfg, int new_enable)
{
	int old_enable;
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	old_enable = cfg->enable;
	if (new_enable != -1) {
		cfg->enable = !!new_enable;
		if (new_enable && cfg->socket < 0)
			ipguard_connect(cfg);
		if (!new_enable && cfg->socket >= 0)
			ipguard_disconnect(cfg);
	}
	return old_enable;
}


MODULE_INTERNAL int
ipguard_set_socket_path(ipguard_cfg_t *cfg, const char *new_socket_path)
{
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	if (NULL == new_socket_path || 0 == *new_socket_path
			|| strlen(new_socket_path) >= sizeof(cfg->socket_path))
		return -1;
	if (0 == strcmp(cfg->socket_path, new_socket_path))
		return 0;
	strcpy(cfg->socket_path, new_socket_path);
	if (cfg->enable && cfg->socket >= 0) {
		ipguard_disconnect(cfg);
		ipguard_connect(cfg);
	}
	return 0;
}


MODULE_INTERNAL int
ipguard_init(ipguard_cfg_t *cfg)
{
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	cfg->enable = IPGUARD_DEF_ENABLE;
	cfg->debug = IPGUARD_DEF_DEBUG;
	cfg->restrictive = IPGUARD_DEF_RESTRICTIVE;
	cfg->socket = -1;
	cfg->timeout = IPGUARD_SERVER_TIMEOUT;
	strcpy(cfg->socket_path, IPGUARD_DEF_SOCKET_PATH);

#if IPGUARD_PTHREADS
	pthread_mutex_init(&(cfg->mutex), NULL);
#endif /* IPGUARD_PTHREADS */

#if defined(IPGUARD_APACHE_MODULE) || defined(IPGUARD_NGINX_MODULE)
	cfg->req = NULL;
#endif /* IPGUARD_APACHE_MODULE */

	return 0;
}


#if !defined(IPGUARD_APACHE_MODULE) && !defined(IPGUARD_NGINX_MODULE)
MODULE_INTERNAL int
ipguard_shutdown(ipguard_cfg_t *cfg)
{
	if (NULL == cfg)
		cfg = ipguard_get_common_cfg();

	ipguard_disconnect(cfg);
	cfg->enable = 0;
#if IPGUARD_PTHREADS
	pthread_mutex_destroy(&(cfg->mutex));
#endif /* IPGUARD_PTHREADS */
#if defined(IPGUARD_APACHE_MODULE) || defined(IPGUARD_NGINX_MODULE)
	cfg->req = NULL;
#endif /* IPGUARD_APACHE_MODULE */
	return 0;
}
#endif /* !IPGUARD_APACHE_MODULE */


