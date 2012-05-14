/* ========================================================================
 * Copyright 2010 Vitki <vitki@vitki.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/**
 * ngx_http_ipguard_module.c
 * Nginx IPGuard module
 * SVN Id: $Id$
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/***********************************
 * Logging
 */

static int ipguard_debug;

#define IPGUARD_LOG_DEBUG   NGX_LOG_WARN

#define ipguard_ngx_log(log,verb,args...) \
        do { \
            ngx_uint_t _verb = (verb); \
            ngx_log_t *_log = (log); \
            if (ipguard_debug && _verb > IPGUARD_LOG_DEBUG) \
                _verb = IPGUARD_LOG_DEBUG; \
            if (ipguard_debug || _verb <= _log->log_level) \
                ngx_log_error_core(_verb, _log, 0, args); \
        } while(0)


/***********************************
 * dirty! dirty! do not link, just include
 */

#define ipguard_lock()		(0)
#define ipguard_unlock()	(0)

#define IPGUARD_NGINX_MODULE 1
#define IPGUARD_PTHREADS 0
#define MODULE_INTERNAL static
#define MODULE_LOG_LEVEL IPGUARD_LOG_DEBUG
typedef ngx_http_request_t request_rec;
#include "ipguard-client.c"


/***********************************
 * Prototypes
 */

#define IPGUARD_ERR_STATUS NGX_HTTP_FORBIDDEN

extern ngx_module_t ngx_http_ipguard_module;

#define ngx_strcasecmp_c(ns,cs) ((ns).len == sizeof(cs)-1 && \
                            ! ngx_strncasecmp((ns).data, (u_char*)(cs), sizeof(cs)-1))

#define ngx_strcmp_eq(ns1,ns2) ((ns1).len == (ns2).len && \
                            ! ngx_strncmp((ns1).data, (ns2).data, (ns1).len))

/***********************************
 * Data types
 */

/* Module configuration struct */
typedef struct {
    ngx_flag_t check;
} ngx_ipguard_loc_t;

typedef struct
{
	ngx_flag_t enable;
	ngx_flag_t restrictive;
	ngx_flag_t debug;
	ngx_str_t  socket_path;
	ngx_int_t  timeout;
	ngx_int_t  err_status;
	ipguard_cfg_t *cfg;
} ngx_ipguard_srv_t;


/*
 *  Configuration
 */

static char *
ngx_ipguard_post_debug (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *fp = conf;
    ipguard_debug = *fp;
    return NGX_CONF_OK;
}

static char *
ngx_ipguard_post_ipguard (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_ipguard_srv_t *srv;
    ngx_flag_t *fp = conf;
    if (*fp) {
        srv = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ipguard_module);
        srv->enable = 1;
    }
    return NGX_CONF_OK;
}

static char *
ngx_ipguard_post_timeout (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_int_t *np = conf;
    if (*np < 0 || *np > 60)
        return "ipguard: timeout should be between 0 and 60 seconds";
    return NGX_CONF_OK;
}

static ngx_conf_post_t ngx_ipguard_conf_debug = { ngx_ipguard_post_debug };
static ngx_conf_post_t ngx_ipguard_conf_ipguard = { ngx_ipguard_post_ipguard };
static ngx_conf_post_t ngx_ipguard_conf_timeout = { ngx_ipguard_post_timeout };

static const ngx_command_t
ngx_ipguard_commands[] = {

    /* ... */
    { ngx_string("ipguard_socket"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_ipguard_srv_t, socket_path),
      NULL },

    /* ... */
    { ngx_string("ipguard_restrictive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_ipguard_srv_t, restrictive),
      NULL },

    /* ... */
    { ngx_string("ipguard_debug"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_ipguard_srv_t, debug),
      &ngx_ipguard_conf_debug },

    /* ... */
    { ngx_string("ipguard_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_ipguard_srv_t, timeout),
      &ngx_ipguard_conf_timeout },

    /* ... */
    { ngx_string("ipguard_err_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_ipguard_srv_t, err_status),
      NULL },

    /* ... */
    { ngx_string("ipguard"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_ipguard_loc_t, check),
      &ngx_ipguard_conf_ipguard },

    ngx_null_command
};


static void *
ngx_ipguard_srv_create (ngx_conf_t *cf)
{
    ngx_ipguard_srv_t *srv = ngx_pcalloc(cf->pool, sizeof(ngx_ipguard_srv_t));
    if (!srv)
        return NULL;
    srv->enable = NGX_CONF_UNSET;
    srv->restrictive = NGX_CONF_UNSET;
    srv->debug = NGX_CONF_UNSET;
    srv->timeout = NGX_CONF_UNSET;
    srv->err_status = NGX_CONF_UNSET;
    return (void *) srv;
}

static char *
ngx_ipguard_srv_merge (ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ipguard_srv_t *prv = parent;
    ngx_ipguard_srv_t *srv = child;
    char *socket_path;
    ngx_http_core_srv_conf_t *core_scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    ngx_conf_merge_value(srv->enable, prv->enable, IPGUARD_DEF_ENABLE);
    ngx_conf_merge_value(srv->restrictive, prv->restrictive, IPGUARD_DEF_RESTRICTIVE);
    ngx_conf_merge_value(srv->debug, prv->debug, IPGUARD_DEF_DEBUG);
    ngx_conf_merge_value(srv->timeout, prv->timeout, IPGUARD_SERVER_TIMEOUT);
    ngx_conf_merge_value(srv->err_status, prv->err_status, IPGUARD_ERR_STATUS);
    ngx_conf_merge_str_value(srv->socket_path, prv->socket_path, IPGUARD_DEF_SOCKET_PATH);

    srv->cfg = ngx_pcalloc(cf->pool, sizeof(ipguard_cfg_t));
    socket_path = ngx_pnalloc(cf->pool, srv->socket_path.len + 1);
    if (!srv->cfg || !socket_path)
        return "not enough memory for ipguard";

    if (srv->socket_path.len)
        ngx_memcpy((u_char *) socket_path, srv->socket_path.data, srv->socket_path.len);
    socket_path[srv->socket_path.len] = '\0';

	ipguard_init(srv->cfg);
    ipguard_lock();
    ipguard_set_debug(srv->cfg, srv->debug);
    ipguard_set_restrictive(srv->cfg, srv->restrictive);
    ipguard_set_socket_path(srv->cfg, socket_path);
    ipguard_set_enable(srv->cfg, srv->enable);
    ipguard_set_timeout(srv->cfg, srv->timeout);
    ipguard_unlock();

    ipguard_ngx_log(cf->log, NGX_LOG_DEBUG,
        "ipguard(%V): enable=%d restrict=%d debug=%d timeout=%d status=%d socket=%s",
        &core_scf->server_name, srv->enable, srv->restrictive,
        srv->debug, srv->timeout, srv->err_status, socket_path);

    return NGX_CONF_OK;
}

static void *
ngx_ipguard_loc_create (ngx_conf_t *cf)
{
    ngx_ipguard_loc_t *loc = ngx_pcalloc(cf->pool, sizeof(ngx_ipguard_loc_t));
    if (!loc)
        return NULL;
    loc->check = NGX_CONF_UNSET;
    return (void *) loc;
}

static char *
ngx_ipguard_loc_merge (ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ipguard_loc_t  *prv = parent;
    ngx_ipguard_loc_t  *loc = child;
    ngx_ipguard_srv_t *srv;

    ngx_conf_merge_value(loc->check, prv->check, 0);
    if (loc->check) {
        srv = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ipguard_module);
        srv->enable = 1;
    }

    return NGX_CONF_OK;
}


/* Authentication */

static int
ngx_ipguard_auth_hook (ngx_http_request_t * r)
{
    ngx_ipguard_loc_t *loc = ngx_http_get_module_loc_conf(r, ngx_http_ipguard_module);
    ngx_ipguard_srv_t *srv = ngx_http_get_module_srv_conf(r, ngx_http_ipguard_module);
	char reply[80];
    int ret;

    /* pass if subrequest */
    if (r != r->main)
        return NGX_OK;

    /*ipguard_ngx_log(r->connection->log, NGX_LOG_DEBUG,
                    "... ipguard check loc=%p check=%d uri=%V",
                    loc, loc ? loc->check : -1, &r->uri);*/

    /* pass if not enabled */
    if (!loc || !loc->check || !srv || !srv->enable)
        return NGX_OK /* DECLINED */;

    /* pass if request is for favicon or robots */
    if (ngx_strcasecmp_c (r->uri, "/favicon.ico")
        || ngx_strcasecmp_c (r->uri, "/robots.txt"))
        return NGX_OK;

	srv->cfg->req = r;
	ipguard_lock();
	ret = ipguard_check_sockaddr(srv->cfg, r->connection->sockaddr,
								reply, sizeof(reply));
	ipguard_unlock();
	srv->cfg->req = NULL;

    ipguard_ngx_log(r->connection->log, NGX_LOG_DEBUG,
                    "ipguard check result: ret=%d uri=%V",
                    ret, &r->uri);

    return (ret == IPGUARD_OK ? NGX_OK : srv->err_status);
}

/* Initialize after config file commands have been processed */

static ngx_int_t
ngx_ipguard_init (ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *core_cf;

    core_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (! (h = ngx_array_push(&core_cf->phases[NGX_HTTP_ACCESS_PHASE].handlers)))
        return NGX_ERROR;
    *h = ngx_ipguard_auth_hook;

    return NGX_OK;
}


static ngx_http_module_t
ngx_http_ipguard_module_ctx = {
    NULL,                     /* preconfiguration */
    ngx_ipguard_init,         /* postconfiguration */
    NULL,                     /* create main configuration */
    NULL,                     /* init main configuration */
    ngx_ipguard_srv_create,   /* create server configuration */
    ngx_ipguard_srv_merge,    /* merge server configuration */
    ngx_ipguard_loc_create,   /* create location configuration */
    ngx_ipguard_loc_merge     /* merge location configuration */
};

ngx_module_t
ngx_http_ipguard_module = {
    NGX_MODULE_V1,
    &ngx_http_ipguard_module_ctx,          /* module context */
    (ngx_command_t *)ngx_ipguard_commands, /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* END, SVN Id: $Id$ */

