/* 
 * Copyright (C) 2017 Ng Chiang Lin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/*
Simple nginx filter module to 
insert a string of text after the html <head>
tag. For example, it can insert a external javascript
to a html page. 

The <head> must appear within the first 
512 characters of the document. 
An optional configuration directive
allows a blank page to be shown if 
the <head> tag is not found. If there is
more than one <head> tag, the text will
be inserted only after the first <head>
tag. 

Ng Chiang Lin
Dec 2017

*/


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define HF_MAX_STACK_SZ 512
#define HF_MAX_CONTENT_SZ 512

#if (NGX_DEBUG)
#define HT_HEADF_DEBUG 1
#else
#define HT_HEADF_DEBUG 0
#endif

/*
stack for parsing html
*/
typedef struct 
{
u_char data[HF_MAX_STACK_SZ];
ngx_int_t top;
}
headfilter_stack_t;


/*
module data struct for maintaining
state per request
*/
typedef struct
{
ngx_uint_t  last;
ngx_uint_t  count;
ngx_uint_t  found;
ngx_uint_t  index;
ngx_uint_t  starttag; 
ngx_uint_t  tagquote;
ngx_uint_t  tagsquote;
headfilter_stack_t stack;
ngx_chain_t  *free;
ngx_chain_t  *busy;
ngx_chain_t  *out;
ngx_chain_t  *in;
ngx_chain_t  **last_out;
}
ngx_http_html_head_filter_ctx_t;


/* 
Configuration struct for module
*/
typedef struct
{
ngx_str_t insert_text;
ngx_flag_t block;
}
ngx_http_html_head_filter_loc_conf_t; 

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/* Function prototypes */
static ngx_int_t ngx_http_html_head_init(ngx_conf_t * cf);
static void * ngx_http_html_head_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_html_head_header_filter(ngx_http_request_t *r );
static ngx_int_t ngx_http_html_head_body_filter(ngx_http_request_t *r, 
                                                ngx_chain_t *in);
static ngx_int_t ngx_test_content_type(ngx_http_request_t *r);
static ngx_int_t ngx_test_content_compression(ngx_http_request_t *r);
static void ngx_init_stack(headfilter_stack_t *stack);
static ngx_int_t push(u_char c, headfilter_stack_t *stack);

static ngx_int_t ngx_parse_buf_html(ngx_http_html_head_filter_ctx_t *ctx, 
                                    ngx_http_request_t *r);

static ngx_int_t ngx_process_tag(ngx_http_html_head_filter_ctx_t *ctx, 
                                 ngx_http_request_t *r);

static ngx_int_t ngx_html_insert_output(
                    ngx_http_html_head_filter_ctx_t *ctx, 
                    ngx_http_request_t *r,
                    ngx_http_html_head_filter_loc_conf_t *slcf);

                    
/*
Module directives
*/
static ngx_command_t ngx_http_html_head_filter_commands[] =
{
   {
     ngx_string("html_head_filter"), //Module Directive name
     NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, //Directive argument 
     ngx_conf_set_str_slot, //Handler function 
     NGX_HTTP_LOC_CONF_OFFSET, //Save to loc config 
     offsetof(ngx_http_html_head_filter_loc_conf_t, insert_text),//loc para
     NULL
   },
   
   {
     ngx_string("html_head_filter_block"), //Module Directive name
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, //Directive argument
     ngx_conf_set_flag_slot, //Handler function 
     NGX_HTTP_LOC_CONF_OFFSET, //Save to loc config 
     offsetof(ngx_http_html_head_filter_loc_conf_t, block),//loc para
     NULL
   },
   
   ngx_null_command
};


/*
Module context 
*/
static ngx_http_module_t  ngx_http_html_head_filter_ctx =
{
    NULL, //Pre config
    ngx_http_html_head_init, //Post config
    NULL, //Create main config
    NULL, //Init main config
    NULL, //Create server config
    NULL, //Merge server config
    ngx_http_html_head_create_conf, //Create loc config
    NULL //Merge loc config
};


/*
Module definition
*/
ngx_module_t  ngx_http_html_head_filter_module = 
{
    NGX_MODULE_V1,
    &ngx_http_html_head_filter_ctx,     /* module context */
    ngx_http_html_head_filter_commands, /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                                  
    NULL,                                  
    NULL,                                  
    NULL,                                  
    NULL,                                  
    NULL,                                 
    NULL,                                  
    NGX_MODULE_V1_PADDING
};



/* Creates the module location config struct */
static void* 
ngx_http_html_head_create_conf(ngx_conf_t *cf)
{

    ngx_http_html_head_filter_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_html_head_filter_loc_conf_t));
    if(conf == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "[Html_head filter]: ngx_http_html_head_create_conf "
            " cannot allocate memory for config");
        return NGX_CONF_ERROR;
    }

    conf->block = NGX_CONF_UNSET;
    return conf;

}


/* Function to initialize the module */
static ngx_int_t
ngx_http_html_head_init(ngx_conf_t * cfg)
{

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_html_head_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_html_head_body_filter;
 
    return NGX_OK;

}


/*Module function handler to filter http response headers */
static ngx_int_t
ngx_http_html_head_header_filter(ngx_http_request_t *r )
{

    ngx_http_html_head_filter_loc_conf_t *slcf;
    ngx_http_html_head_filter_ctx_t *ctx;
    ngx_uint_t content_length=0; 

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_html_head_filter_module);
    
    
    if(slcf == NULL)
    {
        #if HT_HEADF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[Html_head filter]: ngx_http_html_head_header_filter "
                "null configuration");
        #endif
       
        return ngx_http_next_header_filter(r);
    }
    

    if(slcf->insert_text.len == 0)
    {
        #if HT_HEADF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[Html_head filter]: empty configuration insert text");
        #endif
        
        return ngx_http_next_header_filter(r);
    }
    

    if(r->headers_out.content_type.len == 0 || 
        r->headers_out.content_length_n == 0 ||
        r->header_only )
    {
        #if HT_HEADF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[Html_head filter]: empty content type or "
                "header only ");
        #endif
        
        return ngx_http_next_header_filter(r);
    }
    
     
    if(ngx_test_content_type(r) == 0) 
    {
        #if HT_HEADF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[Html_head filter]: content type not html");
        #endif            
        
        return ngx_http_next_header_filter(r);
    }

    
    if(ngx_test_content_compression(r) != 0)
    {//Compression enabled, don't filter   
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                     "[Html_head filter]: compression enabled");
                     
        return ngx_http_next_header_filter(r);
    }
 
    if(r->headers_out.status != NGX_HTTP_OK)
    {//Response is not HTTP 200   
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                     "[Html_head filter]: http response is not 200");
                     
        return ngx_http_next_header_filter(r);
    }

    r->filter_need_in_memory = 1;

    if (r == r->main) 
    {//Main request 
        content_length = r->headers_out.content_length_n + 
                         slcf->insert_text.len;
        r->headers_out.content_length_n = content_length;      
    }
    

    ctx = ngx_http_get_module_ctx(r, ngx_http_html_head_filter_module);
    if(ctx == NULL)
    {
        ctx = ngx_pcalloc(r->pool, 
                          sizeof(ngx_http_html_head_filter_ctx_t)); 
        
        if(ctx == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[Html_head filter]: cannot allocate ctx"
                          " memory");
                          
            return ngx_http_next_header_filter(r);
        }
        
        ngx_http_set_ctx(r, ctx, ngx_http_html_head_filter_module);
    }
    
    
    return ngx_http_next_header_filter(r);
    
}



/*
Module function handler to filter the html response body
and insert the text string
*/
static ngx_int_t
ngx_http_html_head_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{

    ngx_http_html_head_filter_loc_conf_t *slcf;
    ngx_http_html_head_filter_ctx_t *ctx;
    ngx_chain_t  *cl;
    ngx_buf_t  *b;
    ngx_int_t rc;
    u_char* empty_page = (u_char*)"<!DOCTYPE html><html><head>"
                                  "<meta charset=\"UTF-8\">"
	                              "<title></title></head><body>"
                                  "</body></html>";
                                  

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_html_head_filter_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_html_head_filter_module);

    
    if(slcf == NULL)
    {
        #if HT_HEADF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[Html_head filter]: ngx_http_html_head_body_filter "
                "null configuration");
        #endif
       
        return ngx_http_next_body_filter(r, in);
    }


    if(ctx == NULL)
    {
       ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
            "[Html_head filter]: ngx_http_html_head_body_filter" 
            "unable to get module ctx");
            
       return ngx_http_next_body_filter(r, in);
    }


    if(in == NULL)
    {
       ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
            "[Html_head filter]: input chain is null");
                     
       return ngx_http_next_body_filter(r, in);
    }


    //Copy the incoming chain to ctx-in
    if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) 
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[Html_head filter]: unable to copy"
            " input chain - in");
                     
        return NGX_ERROR;
    }

    ctx->last_out = &ctx->out;
   
    //Loop through all the incoming buffers
    while(ctx->in)
    {	
        ctx->index = 0; 
        if(ctx->found == 0 && ctx->last == 0)
        {		 
            rc = ngx_parse_buf_html(ctx, r);
            if(rc == NGX_OK)
            { //<head> is found
                ctx->found = 1; 
                rc=ngx_html_insert_output(ctx, r, slcf);
			   
                if(rc == NGX_ERROR)
                {
                    return rc; 
                }
            }
            else if(rc == NGX_ERROR)
            {
                ctx->last = 1;
            }	
        }	

        b = ctx->in->buf;

        if(b->last_buf || b->last_in_chain)
        {//Last buffer and <head> not found
         //even if content is less than 512 chars
           if(!ctx->found)
           {
              ctx->last = 1;
           }
        }		
    
        *ctx->last_out=ctx->in;
        ctx->last_out=&ctx->in->next;
        ctx->in = ctx->in->next;
    }

    *ctx->last_out = NULL;
	
    //If <head> is not found and block option is enabled
    if(ctx->last  && slcf->block == 1) 
    {

        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "[Html_head filter]: cannot find <head> "
                      "blocking");

        cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (cl == NULL) 
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                "[Html_head filter]: ngx_http_html_head_body_filter "
                "unable to allocate output chain");
                
            return NGX_ERROR;
        }

        b=cl->buf;
        ngx_memzero(b, sizeof(ngx_buf_t));

        b->tag = (ngx_buf_tag_t) &ngx_http_html_head_filter_module;
        b->memory=1;
        b->pos = empty_page;
        b->last = empty_page + ngx_strlen(empty_page);

        if(r ==r->main)
        {		
            b->last_buf = 1;
        }
        else
        {
            b->last_in_chain = 1; 
        }
        
        ctx->out = cl; 
        ctx->out->next = NULL; 
        r->keepalive = 0;
		
    }
    
   
    rc=ngx_http_next_body_filter(r, ctx->out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                            (ngx_buf_tag_t)&ngx_http_html_head_filter_module);

    ctx->in = NULL; 

    return rc;
    
}


/*
Insert the text into body response buffer
*/
static ngx_int_t 
ngx_html_insert_output(ngx_http_html_head_filter_ctx_t *ctx, 
                       ngx_http_request_t *r, 
                       ngx_http_html_head_filter_loc_conf_t *slcf)
{

    ngx_chain_t  *cl, *ctx_in_new, **ll;
    ngx_buf_t  *b;

    if(ctx->in == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
             "[Html_head filter]: ngx_html_insert_output "
             "text Insertion ctx->in is NULL");
             
        return NGX_ERROR;
    }

				   
    ll = &ctx_in_new;				   
    b=ctx->in->buf;

    if(b->pos + ctx->index + 1 > b->last)
    {//Check that the head tag position does not exceed buffer
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[Html_head filter]: ngx_html_insert_output "
            "invalid input buffer at text insertion");
            
        return NGX_ERROR;          
    }

    cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) 
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[Html_head filter]: ngx_html_insert_output "
            "unable to allocate output chain");
            
        return NGX_ERROR;
    }

    b=cl->buf;
    ngx_memzero(b, sizeof(ngx_buf_t));

    b->tag = (ngx_buf_tag_t) &ngx_http_html_head_filter_module;
    b->memory=1;
    b->pos = ctx->in->buf->pos;
    b->last = b->pos + ctx->index + 1;
    b->recycled = ctx->in->buf->recycled;
    b->flush = ctx->in->buf->flush; 
       
    *ll = cl;  
    ll = &cl->next;
	

    cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) 
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
             "[Html_head filter]: ngx_html_insert_output "
             "unable to allocate output chain");
             
        return NGX_ERROR;
    }

    b=cl->buf;
    ngx_memzero(b, sizeof(ngx_buf_t));
	 
    b->tag = (ngx_buf_tag_t) &ngx_http_html_head_filter_module;
    b->memory=1;
    b->pos=slcf->insert_text.data;
    b->last=b->pos + slcf->insert_text.len;
    b->recycled = ctx->in->buf->recycled;
	 
    *ll = cl;
    ll = &cl->next;
	 

    if(ctx->in->buf->pos + ctx->index + 1 == ctx->in->buf->last )
    {//head tag is in last position of the buffer
   
        b->last_buf = ctx->in->buf->last_buf;
        b->last_in_chain = ctx->in->buf->last_in_chain;
		 
        *ll = ctx->in->next; 
		
	    if(ctx->in->buf->recycled)
	    {//consume existing buffer
	        ctx->in->buf->pos = ctx->in->buf->last;
	    }
	    ctx->in = ctx_in_new;
	    return NGX_OK;
		
    }
     
    
    //tag is within buffer last position, 
    //i.e. ctx->in->buf->pos + ctx->index + 1 < ctx->in->buf->last
    cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) 
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[Html_head filter]: ngx_html_insert_output unable to allocate "
            "output chain");
            
        return NGX_ERROR;
    }

    b=cl->buf;
    ngx_memzero(b, sizeof(ngx_buf_t));

    b->tag = (ngx_buf_tag_t) &ngx_http_html_head_filter_module;
    b->memory=1;
    b->pos = ctx->in->buf->pos + ctx->index + 1;
    b->last = ctx->in->buf->last;
    b->recycled = ctx->in->buf->recycled;
    b->last_buf = ctx->in->buf->last_buf;
    b->last_in_chain = ctx->in->buf->last_in_chain;

    *ll = cl;
    ll = &cl->next;
    *ll = ctx->in->next;
	 
    if(ctx->in->buf->recycled)
    {//consume existing buffer
        ctx->in->buf->pos = ctx->in->buf->last;	
    }
	 
    ctx->in = ctx_in_new; 
	   
    return NGX_OK;

}


/*
Parses the buffer to look for the <head> tag
Returns NGX_OK if found, 
        NGX_AGAIN if not found in this buffer,
        NGX_ERROR if an error occurs.
*/
static ngx_int_t 
ngx_parse_buf_html(ngx_http_html_head_filter_ctx_t *ctx, 
                   ngx_http_request_t *r)
{
    u_char *p, c;
    ngx_int_t rc;
    ngx_buf_t* buf;
	
    if(ctx->in == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[Html_head filter]: ngx_parse_buf_html "
            "unable to parse html ctx->in is NULL");  
            
        return NGX_ERROR;
    }
		
    buf = ctx->in->buf; 

    for(p=buf->pos; p < buf->last; p++)
    {

        c = *p;
        if(ctx->count == HF_MAX_CONTENT_SZ)
        {
            ngx_log_error(NGX_LOG_WARN, 
               r->connection->log, 0, 
               "[Html_head filter]: ngx_parse_buf_html unable "
               "to find <head> tag within 512 "
               "characters");  
               
            return NGX_ERROR;
        } 
        
        switch(c)
        {
            case '<':

                ctx->starttag=1;
                if(!ctx->tagquote && ! ctx->tagsquote)
                {
                   ngx_init_stack(&ctx->stack);
                }

                if(push(c, &ctx->stack) == -1)
                {
                      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                        "[Html_head filter]: ngx_parse_buf_html "
                        "parse stack is full");  
                         
                      return NGX_ERROR;
                }
                
                break;

            case '>':

                if(ctx->starttag)
                {
                    if(push(c, &ctx->stack) == -1)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");  
                            
                        return NGX_ERROR;
                    }

                    if(!ctx->tagquote && !ctx->tagsquote)
                    {    
                        ctx->starttag = 0; 
                        //Process the tag
                        rc = ngx_process_tag(ctx,r);

                        if(rc == NGX_OK)
                        {
                            return NGX_OK;
                        }
                        else if(rc == NGX_ERROR)
                        {
                            return NGX_ERROR; 
                        }
                
                    }
                }

                break;

            case '\"':

                if(ctx->starttag && ctx->tagsquote==0 && ctx->tagquote==0 )
                {
                    ctx->tagquote=1;
                    if(push(c, &ctx->stack) == -1)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");  
                            
                        return NGX_ERROR;
                    }
                }
                else if(ctx->starttag && ctx->tagsquote==0 && ctx->tagquote)
                {
                    ctx->tagquote=0; 
                    if(push(c, &ctx->stack) == -1)
                    {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");
                            
                        return NGX_ERROR;
                    }
            
                }
                else if(ctx->starttag && ctx->tagsquote)
                {
                    if(push(c, &ctx->stack) == -1)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");
                            
                        return NGX_ERROR;
                    }
                }
          
                break;

            case '\'':

                if(ctx->starttag && ctx->tagquote == 0 && ctx->tagsquote == 0)
                {
                    ctx->tagsquote = 1;
                    if(push(c, &ctx->stack) == -1)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");
                            
                        return NGX_ERROR;
                    }  
                }   
                else if(ctx->starttag && ctx->tagquote==0 && ctx->tagsquote)
                {
                    ctx->tagsquote = 0;
                    if(push(c, &ctx->stack) == -1)
                    {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");
                            
                        return NGX_ERROR;
                    }
                } 
                else if(ctx->starttag && ctx->tagquote)
                {
                    if(push(c, &ctx->stack) == -1)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");
                            
                        return NGX_ERROR;
                    }
                }

                break;

            default:
         
                if(ctx->starttag)
                {
                    if(push(c, &ctx->stack) == -1)
                    {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                            "[Html_head filter]: ngx_parse_buf_html "
                            "parse stack is full");
                            
                        return NGX_ERROR;
                    }
                }

        }

        ctx->count++;
        ctx->index++;
    }

    return NGX_AGAIN;
}


/* 
   Check if a html tag is the <head> tag 
   The head tag can be a mixture of upper or lower case 
   and can have leading and trailing spaces. It cannot
   have attributes. The tag cannot exceed 512 chars.
   Returns NGX_OK if it is <head>, NGX_AGAIN to continue processing,
   NGX_ERROR if an error occurs
   
*/
static ngx_int_t 
ngx_process_tag(ngx_http_html_head_filter_ctx_t *ctx, 
                ngx_http_request_t *r)
{
    u_char tmp[HF_MAX_STACK_SZ + 1], *start, *last, *tagstr;
    ngx_uint_t i;
    ngx_uint_t len = ctx->stack.top + 1;

    if(len < HF_MAX_STACK_SZ)
    {
        if(push('\0', &ctx->stack) == -1)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                "[Html_head filter]: ngx_process_tag "
                "parse stack is full");  
                         
            return NGX_ERROR;
        }
    
        tagstr = ctx->stack.data; 
         
    }
    else
    {
        for(i=0;i<len;i++)
        {
            tmp[i] = ctx->stack.data[i];   
        }

        tmp[i]='\0';
        tagstr = tmp;
    }

    //Remove < and >
    start = tagstr +1; 
    last = tagstr + len -2; 

    //Remove leading spaces
    while(isspace(*start) && (start < last)) start++;

    //Remove trailing spaces
    while(isspace(*last) && (start < last)) last--; 
    *(last + 1) = '\0';

    for(i=0;start[i];i++)
    {
        start[i]=ngx_tolower(start[i]);
    }

    if(ngx_strcmp(start, (u_char*)"head") == 0 )
    {
        return NGX_OK;
    }

    return NGX_AGAIN;
}


/*
Check if the content is text/html 
Returns true if text/html is present, false otherwise
*/
static ngx_int_t
ngx_test_content_type(ngx_http_request_t *r)
{
    ngx_str_t tmp;

    if(r->headers_out.content_type.len == 0)
    {
        return 0;
    } 

    tmp.len = r->headers_out.content_type.len;
    tmp.data = ngx_pcalloc(r->pool, sizeof(u_char) * tmp.len ); 

    if(tmp.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[Html_head filter]: ngx_test_content_type "
            "cannot allocate buffer for content type check");
        return 0;
    }

    ngx_strlow(tmp.data, r->headers_out.content_type.data, tmp.len); 

    if(ngx_strnstr(tmp.data, "text/html", 
                  r->headers_out.content_type.len) != NULL)
    {
        return 1;
    }
   
    return 0; 
    
}


/*
Check if the content encoding is compressed using either
gzip, deflate, compress or br (Brotli)
Returns true if compression is enabled, 
false if it cannot determine compression
*/
static ngx_int_t
ngx_test_content_compression(ngx_http_request_t *r)
{
    ngx_str_t tmp;
    
    if(r->headers_out.content_encoding == NULL)
    {//Cannot determine encoding, assume no compression
        return 0; 
    }

    if(r->headers_out.content_encoding->value.len == 0 )
    {
        return 0; 
    }

    tmp.len = r->headers_out.content_encoding->value.len;
    tmp.data = ngx_pcalloc(r->pool, sizeof(u_char) * tmp.len );

    if(tmp.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[Html_head filter]: ngx_test_content_compression"
            " cannot allocate buffer for compression check");
            
        return 0;
    }

    ngx_strlow(tmp.data, 
               r->headers_out.content_encoding->value.data, tmp.len); 


    
    if( tmp.len >= (sizeof("gzip") -1) && 
        ngx_strncmp(tmp.data, (u_char*)"gzip" , tmp.len) == 0 )
    {
        return 1; 
    }
    
    if( tmp.len >= (sizeof("deflate") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"deflate" , tmp.len) == 0 )
    {
        return 1; 
    }
    
    if( tmp.len >= (sizeof("compress") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"compress" , tmp.len) == 0 )
    {
        return 1; 
    }
    
   
    if( tmp.len >= (sizeof("br") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"br" , tmp.len) == 0 )
    {
        return 1; 
    }
        
    //Fail safe to false if compression cannot be determined
    return 0; 
}

/*
Initializes the stack structure
*/
static void 
ngx_init_stack(headfilter_stack_t *stack)
{
    ngx_memset(stack, 0 , sizeof(headfilter_stack_t)); 
    stack->top = -1; 
}

/*
Push a u_char into the stack 
Returns -1 if out of stack space 
*/
static ngx_int_t 
push(u_char c, headfilter_stack_t *stack)
{

    if(stack->top == (HF_MAX_STACK_SZ -1) )
       return -1;
    
    stack->top++;
    stack->data[stack->top] = c;
    return 0;    
}



