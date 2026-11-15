#include "d2s_outcome.h"
#include <string.h>
#include <strings.h>
d2s_outcomes d2s_outcome_evaluate(const d2s_ver_result *r,const d2s_effect_context *c){
    d2s_outcomes out={D2S_TRANSPORT_UNKNOWN,D2S_APPLICATION_UNKNOWN,D2S_EFFECT_UNCONFIRMED};
    if(!r||r->local_refusal||r->unsupported)return out;
    if(r->level>=D2S_VER_TRANSPORT)out.transport_outcome=D2S_TRANSPORT_CONNECTED;
    if(r->replay_proof)out.transport_outcome=D2S_TRANSPORT_TLS_REPLY;
    else if(r->level>=D2S_VER_HANDSHAKE)out.transport_outcome=D2S_TRANSPORT_TLS_ESTABLISHED;
    if(!r->replay_proof&&r->level>=D2S_VER_HANDSHAKE&&r->status>=100&&r->status<=599)out.transport_outcome=D2S_TRANSPORT_HTTP_RESPONSE;
    if(r->replay_proof)out.application_outcome=D2S_APPLICATION_UNKNOWN;
    else if(r->cloudflare_challenge||r->level==D2S_VER_CHALLENGE)out.application_outcome=D2S_APPLICATION_CHALLENGE;
    else if(r->level==D2S_VER_BLOCKPAGE||r->http_outcome==D2S_HTTP_BLOCKED)out.application_outcome=D2S_APPLICATION_BLOCKED;
    else if(r->level==D2S_VER_DENIED||r->status==451||r->http_outcome==D2S_HTTP_LEGAL_DENIAL)out.application_outcome=D2S_APPLICATION_LEGAL_DENIAL;
    else if(out.transport_outcome==D2S_TRANSPORT_HTTP_RESPONSE){
        if(r->status==401||r->status==403)out.application_outcome=D2S_APPLICATION_ACCESS_DENIED;
        else if(r->status==429)out.application_outcome=D2S_APPLICATION_RATE_LIMIT;
        else if(r->status>=500)out.application_outcome=D2S_APPLICATION_SERVER_ERROR;
        else if(r->status>=300&&r->status<400&&r->status!=304)out.application_outcome=D2S_APPLICATION_REDIRECT;
        else if(r->status==101&&r->level==D2S_VER_APPLICATION&&r->body_complete)out.application_outcome=D2S_APPLICATION_SUCCESS;
        else if(!r->body_complete||!r->body_framing_valid||r->local_limit)out.application_outcome=D2S_APPLICATION_INCOMPLETE;
        else if((r->status>=200&&r->status<300)||r->status==304||
            (r->status==101&&r->level==D2S_VER_APPLICATION))out.application_outcome=D2S_APPLICATION_SUCCESS;
        else out.application_outcome=D2S_APPLICATION_NEUTRAL;
    }
    if(!c||!c->strategy_applied||!c->comparable||r->local_limit)return out;
    if(c->baseline_available){out.strategy_effectiveness=D2S_EFFECT_NOT_NEEDED;return out;}
    if(!c->baseline_blocked)return out;
    if(out.transport_outcome<D2S_TRANSPORT_TLS_REPLY){out.strategy_effectiveness=D2S_EFFECT_FAILED;return out;}
    if(!c->data_cut)out.strategy_effectiveness=D2S_EFFECT_TRANSPORT_IMPROVED;
    if(out.application_outcome==D2S_APPLICATION_SUCCESS&&r->budget!=D2S_BUDGET_CUT&&
        (!c->data_cut||r->budget==D2S_BUDGET_PASSED))out.strategy_effectiveness=D2S_EFFECT_CONFIRMED;
    return out;
}
const char *d2s_transport_outcome_name(d2s_transport_outcome v){static const char *const names[]={"not_measured","tcp_connected","tls_reply","tls_established","http_response"};return (unsigned)v<sizeof names/sizeof names[0]?names[v]:"not_measured";}
const char *d2s_application_outcome_name(d2s_application_outcome v){static const char *const names[]={"not_measured","success","redirect_unverified","legal_denial","access_denied","rate_limited","server_error","challenge","blocked","incomplete","neutral"};return (unsigned)v<sizeof names/sizeof names[0]?names[v]:"not_measured";}
const char *d2s_strategy_effectiveness_name(d2s_strategy_effectiveness v){static const char *const names[]={"unconfirmed","not_needed","transport_improved","confirmed","failed"};return (unsigned)v<sizeof names/sizeof names[0]?names[v]:"unconfirmed";}

/* A redirect is evidence only for the authenticated origin. Do not fetch
 * its destination or promote this result to application success. */
static int secure_redirect(const d2s_ver_result *r) {
    if (r->status!=301&&r->status!=302&&r->status!=303&&r->status!=307&&r->status!=308) return 0;
    const char *p=r->location;
    if (strncasecmp(p,"https://",8)) return 0;
    p+=8;
    unsigned host=0;
    for (;*p&&*p!='/'&&*p!='?'&&*p!='#';p++) {
        unsigned char c=(unsigned char)*p;
        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')) host++;
        else if(c!='.'&&c!='-'&&c!=':'&&c!='['&&c!=']') return 0;
    }
    if (!host) return 0;
    for (;*p;p++) if ((unsigned char)*p<=0x20||(unsigned char)*p==0x7f||*p=='\\') return 0;
    return 1;
}
int d2s_outcome_http_transport_witness(const d2s_ver_result *r){
    if(!r||r->name_ok!=1||r->local_refusal||r->local_limit||r->unsupported||r->replay_proof||
       !r->body_complete||!r->body_framing_valid||r->budget==D2S_BUDGET_CUT||
       (r->status!=400&&r->status!=401&&r->status!=403&&r->status!=404&&
        r->status!=429&&r->status!=451&&!(r->status>=500&&r->status<=599)&&!secure_redirect(r)))return 0;
    d2s_outcomes o=d2s_outcome_evaluate(r,NULL);
    return o.transport_outcome==D2S_TRANSPORT_HTTP_RESPONSE&&
        (o.application_outcome==D2S_APPLICATION_NEUTRAL||o.application_outcome==D2S_APPLICATION_REDIRECT||
         o.application_outcome==D2S_APPLICATION_ACCESS_DENIED||o.application_outcome==D2S_APPLICATION_LEGAL_DENIAL||
         o.application_outcome==D2S_APPLICATION_RATE_LIMIT||o.application_outcome==D2S_APPLICATION_SERVER_ERROR);
}
