#ifndef D2S_OUTCOME_H
#define D2S_OUTCOME_H
#include "d2s_verify.h"
typedef enum { D2S_TRANSPORT_UNKNOWN,D2S_TRANSPORT_CONNECTED,D2S_TRANSPORT_TLS_REPLY,
    D2S_TRANSPORT_TLS_ESTABLISHED,D2S_TRANSPORT_HTTP_RESPONSE } d2s_transport_outcome;
typedef enum { D2S_APPLICATION_UNKNOWN,D2S_APPLICATION_SUCCESS,D2S_APPLICATION_REDIRECT,
    D2S_APPLICATION_LEGAL_DENIAL,D2S_APPLICATION_ACCESS_DENIED,D2S_APPLICATION_RATE_LIMIT,
    D2S_APPLICATION_SERVER_ERROR,D2S_APPLICATION_CHALLENGE,D2S_APPLICATION_BLOCKED,
    D2S_APPLICATION_INCOMPLETE,D2S_APPLICATION_NEUTRAL } d2s_application_outcome;
typedef enum { D2S_EFFECT_UNCONFIRMED,D2S_EFFECT_NOT_NEEDED,D2S_EFFECT_TRANSPORT_IMPROVED,
    D2S_EFFECT_CONFIRMED,D2S_EFFECT_FAILED } d2s_strategy_effectiveness;
typedef struct {
    int strategy_applied; /* exact current flow, trial and Plan receipt */
    int comparable; /* same endpoint/name/input profile/path, no local failure */
    int baseline_blocked; /* repeated matched direct control, not a SUSPECT */
    int baseline_available;
    int data_cut; /* handshake alone cannot prove recovery of a data cut */
} d2s_effect_context;
typedef struct {
    d2s_transport_outcome transport_outcome;
    d2s_application_outcome application_outcome;
    d2s_strategy_effectiveness strategy_effectiveness;
} d2s_outcomes;
/* Complete authenticated neutral HTTP or HTTPS redirect response: possible TLS witness, never app success. */
int d2s_outcome_http_transport_witness(const d2s_ver_result *);
d2s_outcomes d2s_outcome_evaluate(const d2s_ver_result *,const d2s_effect_context *);
const char *d2s_transport_outcome_name(d2s_transport_outcome);
const char *d2s_application_outcome_name(d2s_application_outcome);
const char *d2s_strategy_effectiveness_name(d2s_strategy_effectiveness);
#endif
