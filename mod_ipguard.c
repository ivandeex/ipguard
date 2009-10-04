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
 * 
 * mod_ipguard.c
 * Apache IP Guardian Module
 * Version 0.1
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#if 1
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_md5.h"
#include "ap_config.h"
#include "ap_release.h"
#include "apr_buckets.h"
#include "apr_file_info.h"
#include "apr_md5.h"
#include "apr_strings.h"
#include "apr_xml.h"
#endif

#include "ipguard.h"

/* dirty! dirty! do not play with libraries, just include */
#include "ipguard-client.c"

module AP_MODULE_DECLARE_DATA ipguard_module;

typedef struct ipguard_srv_cfg {
	int enable;
	int debug;
	int restrictive;
	char *socket_path;
} ipguard_srv_cfg;

#define IPGUARD_UNSET	-1
#define IPGUARD_OFF		0
#define IPGUARD_ON		1

static void *
ipguard_create_server_config(apr_pool_t *pool, server_rec *svr)
{
	ipguard_srv_cfg *c = apr_pcalloc(pool, sizeof(ipguard_srv_cfg));
	c->enable = IPGUARD_UNSET;
	c->restrictive = IPGUARD_UNSET;
	c->debug = IPGUARD_UNSET;
	c->socket_path = NULL;
	return c;
}


static void *
ipguard_merge_server_config(apr_pool_t *pool, void *_base, void *_add)
{
	ipguard_srv_cfg *c = apr_pcalloc(pool, sizeof(ipguard_srv_cfg));
	ipguard_srv_cfg *base = _base;
	ipguard_srv_cfg *add = _add;

	c->enable = add->enable != IPGUARD_UNSET ? add->enable : base->enable;
	c->restrictive = add->restrictive != IPGUARD_UNSET ? add->restrictive : base->restrictive;
	c->debug = add->debug != IPGUARD_UNSET ? add->debug : base->debug;

	c->socket_path = add->socket_path != NULL ? strdup(add->socket_path)
					: base->socket_path != NULL ? strdup(base->socket_path) : NULL;

	return c;
}


static int
ipguard_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *srv)
{
	ipguard_srv_cfg *c = (ipguard_srv_cfg *) ap_get_module_config(&srv->module_config, &ipguard_module);

	if (c->enable != IPGUARD_UNSET)
		ipguard_set_enable(c->enable);
	if (c->restrictive != IPGUARD_UNSET)
		ipguard_set_restrictive(c->restrictive);
	if (c->socket_path != NULL)
		ipguard_set_socket_path(c->socket_path);

    return OK;
}


static int
ipguard_check_access(request_rec *r)
{
	int ret;
	ipguard_srv_cfg *c;
	char reply[80];

	c = (ipguard_srv_cfg *) ap_get_module_config(r->server->module_config,
											&ipguard_module);
	if (c->enable != IPGUARD_ON)
		return OK;

	ret = ipguard_check_ipaddr(r->connection->remote_ip, reply, sizeof(reply));
	ret = (ret == IPGUARD_OK) ? OK : HTTP_FORBIDDEN;

	if (c->debug == IPGUARD_ON) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"mod_ipguard: %s access for %s (%s)",
					ret == OK ? "granted" : "denied",
					r->connection->remote_ip, reply);
	}

	return ret;
}


static void
ipguard_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(ipguard_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_access_checker(ipguard_check_access, NULL, NULL, APR_HOOK_MIDDLE);
}


static const command_rec ipguard_cmds [] = {
	AP_INIT_TAKE1(	"IPGuardEnable", ap_set_flag_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, enable),
					RSRC_CONF, "Enable or disable IPguard (On or Off)" ),
	AP_INIT_TAKE1(	"IPGuardDebug", ap_set_flag_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, debug),
					RSRC_CONF, "Enable or disable debug mode (On or Off)" ),
	AP_INIT_TAKE1(	"IPGuardRestrictive", ap_set_flag_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, restrictive),
					RSRC_CONF, "Be restrictive (On or Off)" ),
	AP_INIT_TAKE1(	"IPGuardSocket", ap_set_string_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, socket_path),
					RSRC_CONF, "Path to IPguard Unix domain socket" ),
	{NULL}
};


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA ipguard_module = {
	STANDARD20_MODULE_STUFF, 
	NULL,							/* create per-dir    config structures */
	NULL,							/* merge  per-dir    config structures */
	ipguard_create_server_config,	/* create per-server config structures */
	ipguard_merge_server_config,	/* merge  per-server config structures */
	ipguard_cmds,					/* table of config file commands       */
	ipguard_register_hooks			/* register hooks                      */
};

