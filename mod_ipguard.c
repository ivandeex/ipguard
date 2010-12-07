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
#include <pthread.h>
#include <sys/socket.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "ap_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_release.h"
#include "apr_buckets.h"
#include "apr_file_info.h"
#include "apr_strings.h"
#include "apr_xml.h"


/* dirty! dirty! do not link, just include */
#define IPGUARD_APACHE_MODULE 1
#define IPGUARD_PTHREADS 0
#define MODULE_INTERNAL static
#define MODULE_LOG_LEVEL APLOG_NOTICE
#include "ipguard-client.c"

module AP_MODULE_DECLARE_DATA ipguard_module;


typedef struct ipguard_srv_cfg_st {
	int init_check;
	int engine;
	int debug;
	int restrictive;
	char *socket_path;
	ipguard_cfg_t *cfg;
} ipguard_srv_cfg;


typedef struct ipguard_dir_cfg_st {
	int check;
} ipguard_dir_cfg;

#define IPGUARD_SET_ENGINE		1
#define IPGUARD_SET_DEBUG		2
#define IPGUARD_SET_RESTRICTIVE	3
#define IPGUARD_SET_SOCKET_PATH	4

#define IPGUARD_UNSET	-1
#define IPGUARD_OFF		0
#define IPGUARD_ON		1

static pthread_mutex_t ipguard_global_mutex = PTHREAD_MUTEX_INITIALIZER;
#define ipguard_lock()		pthread_mutex_lock(&ipguard_global_mutex)
#define ipguard_unlock()	pthread_mutex_unlock(&ipguard_global_mutex)

#define SS_DEBUG 0

#if SS_DEBUG
static char ss_debug_trace[100000]={0};
#define ssdebug(x...) sprintf(ss_debug_trace+strlen(ss_debug_trace),x)
#else
#define ssdebug(x...) do{}while(0)
#endif

static void *
ipguard_create_server_config(apr_pool_t *pool, server_rec *s)
{
	ipguard_srv_cfg *c = apr_pcalloc(pool, sizeof(ipguard_srv_cfg));
	ipguard_cfg_t *cfg = apr_pcalloc(pool, sizeof(ipguard_cfg_t));

	ipguard_init(c->cfg = cfg);
	c->init_check = 0;
	c->engine = IPGUARD_UNSET;
	c->restrictive = IPGUARD_UNSET;
	c->debug = IPGUARD_UNSET;
	c->socket_path = NULL;

	ssdebug("Screate(c=%x,cfg=%x,srv=%s)\n", c, c->cfg, s->defn_name?s->defn_name:"none");
	return c;
}


static void *
ipguard_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD)
{
	ipguard_srv_cfg *c = apr_pcalloc(pool, sizeof(ipguard_srv_cfg));
	ipguard_srv_cfg *base = BASE;
	ipguard_srv_cfg *add = ADD;
	ipguard_cfg_t *cfg = apr_pcalloc(pool, sizeof(ipguard_cfg_t));

	ipguard_init(c->cfg = cfg);
	c->engine = add->engine != IPGUARD_UNSET ? add->engine : base->engine;
	c->restrictive = add->restrictive != IPGUARD_UNSET ? add->restrictive : base->restrictive;
	c->debug = add->debug != IPGUARD_UNSET ? add->debug : base->debug;
	c->socket_path = add->socket_path != NULL ? add->socket_path : base->socket_path;

	ssdebug("Smerge(c=%x,cfg=%x,ena=%d,aena=%d,bena=%d)\n", c, c->cfg, c->engine, add->engine, base->engine);
	return c;
}


static void *
ipguard_create_dir_config(apr_pool_t *pool, char *path)
{
	ipguard_dir_cfg *d = apr_pcalloc(pool, sizeof(ipguard_dir_cfg));

	ssdebug("Dcreate(d=%x,path=%s)\n", d, path);
	d->check = IPGUARD_UNSET;
	return d;
}


static void *
ipguard_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD)
{
	ipguard_dir_cfg *d = apr_pcalloc(pool, sizeof(ipguard_dir_cfg));
	ipguard_dir_cfg *base = BASE;
	ipguard_dir_cfg *add = ADD;

	d->check = add->check != IPGUARD_UNSET ? add->check : base->check;
	ssdebug("Dmerge(d=%x,chk=%d,ah=%d,bh=%d)\n", d, d->check, add->check, base->check);
	return d;
}


static int
ipguard_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	ipguard_srv_cfg *c;

	while (NULL != s) {
		c = (ipguard_srv_cfg *) ap_get_module_config(s->module_config, &ipguard_module);

		ipguard_lock();
		ipguard_set_debug(c->cfg, c->debug);
		ipguard_set_restrictive(c->cfg, c->restrictive);
		ipguard_set_socket_path(c->cfg, c->socket_path);
		ipguard_set_enable(c->cfg, c->engine);
		ipguard_unlock();

		ssdebug("Spost(c=%x,cfg=%x,srv=%s,ena=%d,dbg=%d,sok=%s)\n",
				c, c->cfg, s->defn_name?s->defn_name:"none", c->engine, c->debug,
				c->socket_path ? c->socket_path : "0");

		s = s->next;
	}

	return OK;
}


static int
ipguard_check_access(request_rec *r)
{
	int ret = 0;
	ipguard_srv_cfg *c;
	ipguard_dir_cfg *d;
	char reply[80];

	c = (ipguard_srv_cfg *) ap_get_module_config(r->server->module_config,
												&ipguard_module);
#if SS_DEBUG
	d = ap_get_module_config(r->per_dir_config, &ipguard_module);
	ap_log_rerror(APLOG_MARK, MODULE_LOG_LEVEL, 0, r,
			"mod_ipguard: check acess\nc=%x d=%x ce=%d de=%d sp=\"%s\" c=%x cfg=%x ss_dt=\n%s",
			c, d, c->engine, d->check, c->socket_path, c, c->cfg, ss_debug_trace);
#endif
	if (c->engine != IPGUARD_ON)
		return OK;

	d = ap_get_module_config(r->per_dir_config, &ipguard_module);
	if (d->check != IPGUARD_ON)
		return OK;

	c->cfg->req = r;
	ipguard_lock();
	ret = ipguard_check_ipaddr(c->cfg, r->connection->remote_ip,
								reply, sizeof(reply));
	ipguard_unlock();
	c->cfg->req = NULL;
	ret = (ret == IPGUARD_OK) ? OK : HTTP_FORBIDDEN;

	if (c->debug == IPGUARD_ON || ret != OK) {
		ap_log_rerror(APLOG_MARK, MODULE_LOG_LEVEL, 0, r,
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


static const char *
ipguard_param(cmd_parms *cmd, void *config, const char *value)
{
	int what = (int) cmd->info;
	ipguard_srv_cfg *c;
	int bval = -1;

	c = (ipguard_srv_cfg *) ap_get_module_config(cmd->server->module_config, &ipguard_module);

	if (	0 == apr_strnatcasecmp(value, "1")
			|| 0 == apr_strnatcasecmp(value, "on")
			|| 0 == apr_strnatcasecmp(value, "true")
			|| 0 == apr_strnatcasecmp(value, "yes"))
		bval = 1;
	if (	0 == strcmp(value, "0")
			|| 0 == strcasecmp(value, "off")
			|| 0 == strcasecmp(value, "false")
			|| 0 == strcasecmp(value, "no"))
		bval = 0;

	switch (what) {
		case IPGUARD_SET_ENGINE:
			if (bval == -1)  break;
			c->engine = bval;
			ssdebug("set(c=%x,p=engine,v=%d)\n", c, bval);
			return NULL;
		case IPGUARD_SET_DEBUG:
			if (bval == -1)  break;
			c->debug = bval;
			ssdebug("set(c=%x,p=debug,v=%d)\n", c, bval);
			return NULL;
		case IPGUARD_SET_RESTRICTIVE:
			if (bval == -1)  break;
			c->restrictive = bval;
			ssdebug("set(c=%x,p=restrictive,v=%d)\n", c, bval);
			return NULL;
		case IPGUARD_SET_SOCKET_PATH:
			c->socket_path = apr_pstrdup(cmd->pool, value);
			ssdebug("set(c=%x,p=sockpath,v=%s)\n", c, value);
			return NULL;
		default:
			ssdebug("set(c=%x,p=%d!!,v=%d)\n", c, what, value);
			return apr_psprintf(cmd->pool, "mod_ipguard: invalid command \"%s\"",
								cmd->directive->directive);
	}
	return apr_psprintf(cmd->pool, "mod_ipguard: invalid boolean \"%s\" in \"%s\"",
						value, cmd->directive->directive);
}


static const command_rec ipguard_cmds [] = {
	AP_INIT_TAKE1(	"IPGuardEngine", ipguard_param, (void *) IPGUARD_SET_ENGINE,
					RSRC_CONF, "Enable IPguard engine (On or Off)" ),
	AP_INIT_TAKE1(	"IPGuardDebug", ipguard_param, (void *) IPGUARD_SET_DEBUG,
					RSRC_CONF, "Enable debugging (On or Off)" ),
	AP_INIT_TAKE1(	"IPGuardRestrictive", ipguard_param, (void *) IPGUARD_SET_RESTRICTIVE,
					RSRC_CONF, "Be restrictive (On) or permissive (Off)" ),
	AP_INIT_TAKE1(	"IPGuardSocketPath", ipguard_param, (void *) IPGUARD_SET_SOCKET_PATH,
					RSRC_CONF, "Path to IPguard Unix domain socket" ),
#if 0
	AP_INIT_FLAG(	"IPGuardEngine", ap_set_flag_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, engine),
					RSRC_CONF, "Enable IPguard engine (On or Off)" ),
	AP_INIT_FLAG(	"IPGuardDebug", ap_set_flag_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, debug),
					RSRC_CONF, "Enable debugging (On or Off)" ),
	AP_INIT_FLAG(	"IPGuardRestrictive", ap_set_flag_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, restrictive),
					RSRC_CONF, "Be restrictive (On) or permissive (Off)" ),
	AP_INIT_TAKE1(	"IPGuardSocketPath", ap_set_string_slot,
					(void *) APR_OFFSETOF(ipguard_srv_cfg, socket_path),
					RSRC_CONF, "Path to IPguard Unix domain socket" ),
#endif
	AP_INIT_FLAG(	"IPGuardCheck", ap_set_flag_slot,
					(void *) APR_OFFSETOF(ipguard_dir_cfg, check),
					ACCESS_CONF|OR_AUTHCFG, "Enable IPguard checks (On or Off)" ),
	{NULL}
};


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA ipguard_module = {
	STANDARD20_MODULE_STUFF,
	ipguard_create_dir_config,		/* create per-directory config */
	ipguard_merge_dir_config,		/* merge  per-directory config */
	ipguard_create_server_config,	/* create per-server config */
	ipguard_merge_server_config,	/* merge  per-server config */
	ipguard_cmds,					/* table of config file commands */
	ipguard_register_hooks			/* register hooks */
};

