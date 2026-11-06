/* QUIC wire adapters, and nothing else. d2s_quic_original_measure and
 * d2s_quic_strategy_measure are the runtime adapters for the arm control flow
 * in quicarms.c; no arm ladder lives in this file.
 *
 * Two legacy bodies of the deleted snapshot-derived picker are gone with it,
 * both for the same reason — no production caller could reach them:
 *   - d2s_quic_pick_arm (own 1..255 TTL sweep, separate-IP confirmation);
 *   - the raw-socket fragment sender d2s_quic_ask_frag_hook, its midpoint
 *     builder d2s_quic_build_frag2 and their checksums. The runtime ladder is
 *     quicarms.c (four TTL values, D2S_QUIC_ARM_QUESTIONS_MAX questions), and
 *     the fragment question goes out through quicprobe.c + ipfrag.c
 *     (d2s_ipfrag_shape/d2s_udpfrag_build_ex) — the same code the datapath
 *     puts on the wire, measured by core/test_ipfrag.c. A second builder that
 *     nothing sent could only drift away from the one that ships. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#define _DARWIN_C_SOURCE /* IP_TTL на macOS — см. тот же приём в quicprobe.c */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

/* d2s_quic_sni — им wire_measure читает имя из снятого приветствия. */
#include "d2s_quic.h"
#include "d2s_quicprobe.h"
#include "d2s_quic_arms.h"
#include "d2s_quicsnap.h"

typedef struct {
    uint16_t port;
    char target_sni[256];
    const char *path;
    uint32_t wait_ms, mark;
    d2s_hello initial;
    d2s_quic_form form;
    int has_form;
} original_wire;

static d2s_tally original_probe(const d2s_quic_arm_question *q, void *user, int *sent) {
    original_wire *w=user;
    /* Fragment survival (q->control) asks on NO caller name: donor
       arms.go:204-205 calls buildInitial(neutralName(), ...) inside the
       per-attempt closure, so every repeat gets its own fresh
       z<10 hex>.example.com. The wire hook draws them (quic_ask_arm); the
       control snapshot's name (the scheduler decoy) is never reused here. */
    const char *sni=q->control?NULL:w->target_sni;
    d2s_quic_arm_question with_input=*q;
    if(q->split) { with_input.initial=w->initial;with_input.form=w->has_form?&w->form:NULL; }
    return d2s_quic_ask_arm_hook(&with_input,sni,w->port,w->wait_ms,w->mark,sent);
}

/* Task 39: the arm's data stage on the same address, name and action. */
static d2s_quic_arm_data original_data(const d2s_quic_arm_question *q, void *user) {
    original_wire *w=user;
    d2s_quic_arm_question with_input=*q;
    if(q->split) { with_input.initial=w->initial;with_input.form=w->has_form?&w->form:NULL; }
    return d2s_quic_arm_data_hook(&with_input,w->target_sni,w->path,w->port,w->wait_ms,w->mark);
}

static d2s_quic_arm wire_measure(d2s_quic_arm (*run)(d2s_quic_arm_context *),
    d2s_quic_arm_context *ctx, uint16_t port, d2s_hello trigger, d2s_hello control,
    uint32_t wait_ms, uint32_t mark) {
    original_wire wire={.port=port,.wait_ms=wait_ms,.mark=mark,.path=ctx?ctx->path:NULL};
    wire.initial=trigger;
    d2s_qsnap pack;
    int packed=d2s_qsnap_is(trigger.bytes,trigger.len) && !d2s_qsnap_parse(trigger.bytes,trigger.len,&pack);
    wire.has_form=packed && !d2s_qsnap_form(&pack,&wire.form);
    int named=packed ? d2s_qsnap_sni(&pack,wire.target_sni,sizeof wire.target_sni)
                     : d2s_quic_sni(trigger.bytes,trigger.len,wire.target_sni,sizeof wire.target_sni);
    if(named!=0) {
        wire.target_sni[0]='\0';
        /* У буквальной IP-цели donor ClientHello не содержит SNI, но askArms
           всё равно строит каждый Initial для host. pool[0] — именно
           закреплённый исходный IP (не rotated spare и не SNI контроля). */
        if(ctx && ctx->pool && ctx->n_pool > 0) {
            struct in_addr target_ip;
            if(inet_pton(AF_INET,ctx->pool[0],&target_ip)==1) {
                snprintf(wire.target_sni,sizeof wire.target_sni,"%s",ctx->pool[0]);
            }
        }
    }
    /* The control snapshot does not name the survival question (see
       original_probe); it stays in the signature for the Run caller. */
    (void)control;
    d2s_quic_arm_context local=*ctx;
    local.probe=original_probe; local.user=&wire;
    local.data=original_data; local.data_user=&wire;
    d2s_quic_arm r=run(&local);
    if(ctx->path) snprintf(r.probe_path,sizeof r.probe_path,"%s",ctx->path);
    ctx->next=local.next; ctx->marked=local.marked;
    return r;
}

d2s_quic_arm d2s_quic_original_measure(d2s_quic_arm_context *ctx, uint16_t port,
    d2s_hello trigger, d2s_hello control, uint32_t wait_ms, uint32_t mark) {
    return wire_measure(d2s_quic_original_arms,ctx,port,trigger,control,wait_ms,mark);
}

/* Задача 40: рабочий путь подбора — сначала вопросы стратегии, перебор
   askArms только запасной (d2s_quic_strategy_arms); провод и этап данных
   те же. */
d2s_quic_arm d2s_quic_strategy_measure(d2s_quic_arm_context *ctx, uint16_t port,
    d2s_hello trigger, d2s_hello control, uint32_t wait_ms, uint32_t mark) {
    return wire_measure(d2s_quic_strategy_arms,ctx,port,trigger,control,wait_ms,mark);
}
