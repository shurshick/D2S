#include "d2s_outcome.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void){
    d2s_ver_result r={0};r.fd=-1;
    assert(d2s_outcome_evaluate(&r,NULL).transport_outcome==D2S_TRANSPORT_UNKNOWN);
    d2s_effect_context c={1,1,1,0,0};
    r.level=D2S_VER_APPLICATION;r.status=200;r.body_complete=1;r.body_framing_valid=1;
    d2s_outcomes o=d2s_outcome_evaluate(&r,NULL);assert(o.transport_outcome==D2S_TRANSPORT_HTTP_RESPONSE&&o.application_outcome==D2S_APPLICATION_SUCCESS&&o.strategy_effectiveness==D2S_EFFECT_UNCONFIRMED);
    assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_CONFIRMED);
    c.comparable=0;assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_UNCONFIRMED);c.comparable=1;
    c.strategy_applied=0;assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_UNCONFIRMED);c.strategy_applied=1;
    c.baseline_available=1;assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_NOT_NEEDED);c.baseline_available=0;
    const int codes[]={451,403,503,429,404,302};
    const d2s_application_outcome apps[]={D2S_APPLICATION_LEGAL_DENIAL,D2S_APPLICATION_ACCESS_DENIED,D2S_APPLICATION_SERVER_ERROR,D2S_APPLICATION_RATE_LIMIT,D2S_APPLICATION_NEUTRAL,D2S_APPLICATION_REDIRECT};
    for(unsigned i=0;i<sizeof codes/sizeof codes[0];i++){r.status=codes[i];o=d2s_outcome_evaluate(&r,&c);assert(o.transport_outcome==D2S_TRANSPORT_HTTP_RESPONSE&&o.application_outcome==apps[i]&&o.strategy_effectiveness==D2S_EFFECT_TRANSPORT_IMPROVED);}
    r.status=200;r.local_limit=1;assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_UNCONFIRMED);r.local_limit=0;
    r.body_complete=0;assert(d2s_outcome_evaluate(&r,&c).application_outcome==D2S_APPLICATION_INCOMPLETE);r.body_complete=1;
    c.data_cut=1;assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_UNCONFIRMED);r.budget=D2S_BUDGET_PASSED;assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_CONFIRMED);
    r.budget=D2S_BUDGET_CUT;assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness!=D2S_EFFECT_CONFIRMED);
    c.data_cut=0;r.level=D2S_VER_HANDSHAKE;r.status=0;r.replay_proof=1;o=d2s_outcome_evaluate(&r,&c);assert(o.transport_outcome==D2S_TRANSPORT_TLS_REPLY&&o.application_outcome==D2S_APPLICATION_UNKNOWN&&o.strategy_effectiveness==D2S_EFFECT_TRANSPORT_IMPROVED);
    r.replay_proof=0;r.local_refusal=1;o=d2s_outcome_evaluate(&r,&c);assert(o.transport_outcome==D2S_TRANSPORT_UNKNOWN&&o.strategy_effectiveness==D2S_EFFECT_UNCONFIRMED);
    memset(&r,0,sizeof r);r.fd=-1;r.level=D2S_VER_APPLICATION;r.status=404;r.name_ok=1;
    r.body_complete=r.body_framing_valid=1;
    assert(d2s_outcome_http_transport_witness(&r));r.status=400;assert(d2s_outcome_http_transport_witness(&r));
    const int redirects[]={301,302,303,307,308};
    for(unsigned i=0;i<sizeof redirects/sizeof redirects[0];i++) {
        r.status=redirects[i];strcpy(r.location,"https://www.example.org/login/");
        assert(d2s_outcome_http_transport_witness(&r));
        assert(d2s_outcome_evaluate(&r,&c).application_outcome==D2S_APPLICATION_REDIRECT);
        r.name_ok=0;assert(!d2s_outcome_http_transport_witness(&r));r.name_ok=1;
        r.body_complete=0;assert(!d2s_outcome_http_transport_witness(&r));r.body_complete=1;
    }
    const char *bad[]={"","http://example.org/","https://","https://u@example.org/","https://example.org/\r\nX:1","https://example.org/\\evil"};
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++){strcpy(r.location,bad[i]);assert(!d2s_outcome_http_transport_witness(&r));}
    const int transport_codes[]={401,403,429,451,500,503,599};
    for(unsigned i=0;i<sizeof transport_codes/sizeof transport_codes[0];i++){
        r.status=transport_codes[i];assert(d2s_outcome_http_transport_witness(&r));
        assert(d2s_outcome_evaluate(&r,&c).strategy_effectiveness==D2S_EFFECT_TRANSPORT_IMPROVED);
        r.cloudflare_challenge=1;assert(!d2s_outcome_http_transport_witness(&r));r.cloudflare_challenge=0;
        r.http_outcome=D2S_HTTP_BLOCKED;assert(!d2s_outcome_http_transport_witness(&r));r.http_outcome=0;
    }
    r.status=404;
    r.name_ok=0;assert(!d2s_outcome_http_transport_witness(&r));r.name_ok=1;
    r.body_complete=0;assert(!d2s_outcome_http_transport_witness(&r));r.body_complete=1;
    r.body_framing_valid=0;assert(!d2s_outcome_http_transport_witness(&r));r.body_framing_valid=1;
    r.local_limit=1;assert(!d2s_outcome_http_transport_witness(&r));r.local_limit=0;
    r.level=D2S_VER_BLOCKPAGE;assert(!d2s_outcome_http_transport_witness(&r));r.level=D2S_VER_APPLICATION;
    r.budget=D2S_BUDGET_CUT;assert(!d2s_outcome_http_transport_witness(&r));
    puts("outcomes: HTTP status != causal bypass; comparable control, applied receipt, legal/denial/error, framing, budget and passive limits passed");return 0;
}
