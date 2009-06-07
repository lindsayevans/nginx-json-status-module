/*
 *
 * Based on ngx_http_stub_status_module.c, which is Copyright (C) Igor Sysoev
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);

static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("json_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
      0,
      0,
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

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
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

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    // TODO: read from config json_status_type
    //r->headers_out.content_type.len = sizeof("application/json") - 1;
    //r->headers_out.content_type.data = (u_char *) "application/json";
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";


    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Parsing query string: %V", &r->args);

    /* parse query string */
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

    /* Get callback param from query string */
    ngx_str_t cb;
    cb.data = ngx_pcalloc(r->pool, sizeof(char *));
    cb.len = ngx_sprintf(cb.data, "") - cb.data;

    for(i = 0; i < jj; i++){
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "kv[%i]: %s", i, kv[i]);

	if(strcmp((const char *) kv[i], "callback") == 0){
	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "found match at %i: %s, %s", i, kv[i], kv[i+1]);

	    cb.data = ngx_pcalloc(r->pool, strlen((char *) kv[i+1]) * sizeof(char *));
	    cb.len = ngx_sprintf(cb.data, (char *) kv[i+1]) - cb.data;

	}

    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "callback: %s", cb.data);

    /* parse query string to get callback *
    u_char *query = (u_char *) malloc(ngx_strlen(&r->args)*sizeof(u_char *));
    char *sep = "&";
    char *kvsep = "=";
    char *qs = (char *) malloc(ngx_strlen(&r->args)*sizeof(char *));
    char *kv = (char *) malloc(ngx_strlen(&r->args)*sizeof(char *));
    char *k = (char *) malloc(ngx_strlen(&r->args)*sizeof(char *));
    char *v = (char *) malloc(ngx_strlen(&r->args)*sizeof(char *));
    char *brkt = (char *) malloc(ngx_strlen(&r->args)*sizeof(char *));
    char *brkb = (char *) malloc(ngx_strlen(&r->args)*sizeof(char *));

    v = "";

    ngx_sprintf(query, "%V", (u_char *) &r->args);
    qs = (char *) query;
    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "qs: %s", qs);

    if(ngx_strlen(&r->args) > 0){
 
    for(kv = strtok_r(qs, sep, &brkt);
        kv;
        kv = strtok_r(NULL, sep, &brkt))
    {
	k = strtok_r(kv, kvsep, &brkb);
	v = strtok_r(NULL, kvsep, &brkb);
	//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "k=v: %s=%s", k, v);

	if(!strcmp(k, "callback")){
	   break;
        }

    }

    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "callback: %s", v);

    }
*/
    size = sizeof("{active:,") + NGX_ATOMIC_T_LEN
           + sizeof("accepts:,handled:,requests:,") - 1
           + 6 + 3 * NGX_ATOMIC_T_LEN
           + sizeof("reading:,writing:,waiting:}") + 3 * NGX_ATOMIC_T_LEN;

    if(strlen((char *) cb.data) > 0){
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

    if(strlen((char *) cb.data) > 0){
	b->last = ngx_sprintf(b->last, "%s(", cb.data);
    }
    b->last = ngx_sprintf(b->last, "{active:%uA,", ac);

    b->last = ngx_sprintf(b->last, "accepts:%uA,handled:%uA,requests:%uA,", ap, hn, rq);

    b->last = ngx_sprintf(b->last, "reading:%uA,writing:%uA,waiting:%uA}",
                          rd, wr, ac - (rd + wr));

    if(strlen((char *) cb.data) > 0){
	b->last = ngx_sprintf(b->last, ");");
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ///free(query);
    //free(qs); // : causing malloc error double free
    //free(kv); // : causing malloc error double free
    //free(k); // : causing malloc error double free
    //free(v); // : causing non-aligned pointer being freed error
    //free(brkt); // : causing non-aligned pointer being freed error
    ///free(brkb);

    //free(params[j]);

    return ngx_http_output_filter(r, &out);
}


static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_handler;

    return NGX_CONF_OK;
}

