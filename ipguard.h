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

#ifndef _IPGUARD_CLIENT_H
#define _IPGUARD_CLIENT_H

#if 0
#ifdef __cplusplus
extern "C" {
#endif
#endif

#define IPGUARD_KEEPALIVE 1
#define IPGUARD_SERVER_TIMEOUT 4 /* seconds to wait for reply */

#define IPGUARD_DEF_SOCKET_PATH	"/var/run/ipguard.sock"
#define IPGUARD_DEF_ENABLE		0
#define IPGUARD_DEF_DEBUG		0
#define IPGUARD_DEF_RESTRICTIVE	1

#define IPGUARD_SYSFAIL		(-1)
#define IPGUARD_OK			0
#define IPGUARD_FORBIDDEN	1

#ifndef MODULE_INTERNAL
#define MODULE_INTERNAL
#endif

#if IPGUARD_PTHREADS
#include <pthread.h>
#define ipguard_mutex_lock(cfg)		pthread_mutex_lock((&(cfg)->mutex))
#define ipguard_mutex_unlock(cfg)	pthread_mutex_unlock((&(cfg)->mutex))
#else /* IPGUARD_PTHREADS */
#define ipguard_mutex_lock(cfg)		do{}while(0)
#define ipguard_mutex_unlock(cfg)	do{}while(0)
#endif /* IPGUARD_PTHREADS */

#define IPGUARD_LOG_PREFIX "ipguard: "

typedef struct ipguard_cfg {
	int  enable;
	int  debug;
	int  restrictive;
	char socket_path[256];
	int  socket;
#if IPGUARD_PTHREADS
	pthread_mutex_t mutex;
#endif /* IPGUARD_PTHREADS */
#if defined(IPGUARD_APACHE_MODULE) || defined(IPGUARD_NGINX_MODULE)
	request_rec *req;
#endif /* IPGUARD_APACHE_MODULE */
} ipguard_cfg_t;

MODULE_INTERNAL int ipguard_init (ipguard_cfg_t *cfg);
#if !defined(IPGUARD_APACHE_MODULE) && !defined(IPGUARD_NGINX_MODULE)
MODULE_INTERNAL int ipguard_shutdown (ipguard_cfg_t *cfg);
#endif
MODULE_INTERNAL int ipguard_check_ipaddr (ipguard_cfg_t *cfg, const char *ipaddr, char *answer, int answer_len);
#if !defined(IPGUARD_APACHE_MODULE)
MODULE_INTERNAL int ipguard_check_ip (ipguard_cfg_t *cfg, unsigned long ip, char *answer, int answer_len);
MODULE_INTERNAL int ipguard_check_sockaddr (ipguard_cfg_t *cfg, void *sockaddr_ptr, char *answer, int answer_len);
#endif
MODULE_INTERNAL int ipguard_set_debug (ipguard_cfg_t *cfg, int debug);
MODULE_INTERNAL int ipguard_set_restrictive (ipguard_cfg_t *cfg, int restrictive);
MODULE_INTERNAL int ipguard_set_enable (ipguard_cfg_t *cfg, int enable);
MODULE_INTERNAL int ipguard_set_socket_path (ipguard_cfg_t *cfg, const char *socket_path);

#if 0
#ifdef __cplusplus
}
#endif
#endif

#endif /* IPGUARD_CLIENT_H */

