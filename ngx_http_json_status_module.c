/*
 *
 * Copyright 2009 Lindsay Evans <http://linz.id.au/> 
 * 
 * Based on ngx_http_stub_status_module.c, which is Copyright (C) Igor Sysoev
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void* ngx_http_json_status_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_json_status_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);



typedef struct {
    ngx_str_t	json_status_type;
} ngx_http_json_status_loc_conf_t;

static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("json_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("json_status_type"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_json_status_loc_conf_t, json_status_type),
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_json_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_json_status_create_loc_conf,  /* create location configuration */
    ngx_http_json_status_merge_loc_conf	   /* merge location configuration */
};


ngx_module_t  ngx_http_json_status_module = {
    NGX_MODULE_V1,
    &ngx_http_json_status_module_ctx,      /* module context */
    ngx_http_status_commands,              /* module directives */
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


static ngx_int_t ngx_http_status_handler(ngx_http_request_t *r)
{
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_atomic_int_t   ap, hn, ac, rq, rd, wr;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }


    ngx_http_json_status_loc_conf_t	*cglcf;
    cglcf = ngx_http_get_module_loc_conf(r, ngx_http_json_status_module);

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    // Read mime type from config var
    if(ngx_strlen(&cglcf->json_status_type) > 0){
	r->headers_out.content_type.len = sizeof(&cglcf->json_status_type) - 1;
	r->headers_out.content_type.data = (u_char *) &cglcf->json_status_type;
    }else{
	r->headers_out.content_type.len = sizeof("application/json") - 1;
	r->headers_out.content_type.data = (u_char *) "application/json";
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }


    ngx_str_t cb = ngx_string(""); // Callback name

    if(ngx_strlen(&r->args.data) > 0){

	//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Parsing query string: %V", &r->args);

	/* Parse query string */
	u_char *params[10];
	u_int i = 0, j = 0, k = 0;

	u_char *kv[20];
	u_int ii = 0, jj = 0, kk = 0;

	params[j] = (u_char *) malloc(ngx_strlen(r->args.data)*sizeof(u_char *));
	for(i = 0; i < r->args.len + 1; i++){
	    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "QS char: %i : %c", i, r->args.data[i]);
	    if(i == r->args.len || r->args.data[i] == '&'){
		params[j][k++] = '\0';
		//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Added to stack: %s", params[j]);
		//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "len: %i", strlen((char *) params[j]));

		kv[jj] = (u_char *) malloc(ngx_strlen(r->args.data)*sizeof(u_char *));
		for(ii = 0; ii <= strlen((char *) params[j]); ii++){
		    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "QS KV char: %i : %c", ii, params[j][ii]);
		    if(ii == strlen((char *) params[j]) || params[j][ii] == '='){
			kv[jj][kk++] = '\0';
			//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "   Added to stack: %s", kv[jj]);
			jj++;
			kv[jj] = (u_char *) malloc(ngx_strlen(r->args.data)*sizeof(u_char *));    
			kk = 0;
			continue;
		    }
		    kv[jj][kk] = params[j][ii];
		    kk++;
		}

		j++;
		params[j] = (u_char *) malloc(ngx_strlen(r->args.data)*sizeof(u_char *));    
		k = 0;
		continue;
	    }
	    params[j][k] = r->args.data[i];
	    k++;
	}
	//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "get callback");

	/* Get callback param from query string */
	for(i = 0; i < jj; i++){
	    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "kv[%i]: %s", i, kv[i]);

	    if(strcmp((const char *) kv[i], "callback") == 0){
		//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "found match at %i: %s, %s", i, kv[i], kv[i+1]);

		cb.data = ngx_pcalloc(r->pool, strlen((char *) kv[i+1]) * sizeof(char *));
		cb.len = ngx_sprintf(cb.data, (char *) kv[i+1]) - cb.data;

	    }

	}
	//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "callback: %s", cb.data);

    }

    /* Build response */
    size = sizeof("{active:,") + NGX_ATOMIC_T_LEN
           + sizeof("accepts:,handled:,requests:,") - 1
           + 6 + 3 * NGX_ATOMIC_T_LEN
           + sizeof("reading:,writing:,waiting:}") + 3 * NGX_ATOMIC_T_LEN;

    if(ngx_strlen(cb.data) > 0){
	size += sizeof(cb.data) + sizeof("();") + NGX_ATOMIC_T_LEN;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;

    if(ngx_strlen(cb.data) > 0){
	b->last = ngx_sprintf(b->last, "%s(", cb.data);
    }
    b->last = ngx_sprintf(b->last, "{active:%uA,", ac);

    b->last = ngx_sprintf(b->last, "accepts:%uA,handled:%uA,requests:%uA,", ap, hn, rq);

    b->last = ngx_sprintf(b->last, "reading:%uA,writing:%uA,waiting:%uA}",
                          rd, wr, ac - (rd + wr));

    if(ngx_strlen(cb.data) > 0){
	b->last = ngx_sprintf(b->last, ");");
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_handler;

    return NGX_CONF_OK;
}

static void *
ngx_http_json_status_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_json_status_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_json_status_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    //conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_json_status_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_json_status_loc_conf_t *prev = parent;
    ngx_http_json_status_loc_conf_t *conf = child;

    //ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->json_status_type, prev->json_status_type, "");

    //if(conf->enable)
    //    ngx_http_json_status_init(conf);

    return NGX_CONF_OK;
}

