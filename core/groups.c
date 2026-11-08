#include <string.h>
#include "include/d2s_domain.h"
#include "include/d2s_groups.h"
#include "../runtime/d2s_protocol.h"


int d2s_group_key_make(d2s_group_key *key,uint8_t transport,uint8_t family,
    uint8_t shape,const char *path,const char *origin) {
    if(!key || !path || !origin || strlen(path)>=sizeof key->probe_path ||
       strlen(origin)>=sizeof key->ech_origin) return -1;
    memset(key,0,sizeof *key);
    key->transport=transport; key->family=family; key->shape=shape;
    strcpy(key->probe_path,path); strcpy(key->ech_origin,origin);
    return 0;
}

int d2s_group_key_same(const d2s_group_key *a,const d2s_group_key *b) {
    return a && b && a->transport==b->transport && a->family==b->family &&
        a->shape==b->shape && !strcmp(a->probe_path,b->probe_path) &&
        !strcmp(a->ech_origin,b->ech_origin);
}
static int valid(const d2s_group_observation *o) {
    if(!o || !memchr(o->name,0,sizeof o->name) ||
       !memchr(o->plan_id,0,sizeof o->plan_id) ||
       !memchr(o->key.probe_path,0,sizeof o->key.probe_path) ||
       !memchr(o->key.ech_origin,0,sizeof o->key.ech_origin)) return 0;
    if((o->key.family!=4 && o->key.family!=6) ||
       !((o->key.transport==6 && (o->key.shape==1 || o->key.shape==2 || o->key.shape==6 ||
          (o->key.shape>=D2S_TCP_SHAPE_MODERN_NO_TS && o->key.shape<=D2S_TCP_SHAPE_MAX))) ||
         (o->key.transport==17 && o->key.shape==3))) return 0;
    if(o->evidence!=1 && o->evidence!=2 && o->evidence!=4 && o->evidence!=8) return 0;
    return (o->evidence!=D2S_GROUP_BLOCKED_CONFIRMED &&
            o->evidence!=D2S_GROUP_PLAN_FAILED) || o->plan_id[0];
}
/* Normalized names, checked against PSL before entering this model. */
static int member(const char *name,const char *suffix) {
    size_t n=strlen(name),z=strlen(suffix);
    return n>=z && !strcmp(name+n-z,suffix) && (n==z || name[n-z-1]=='.');
}
static int negative(const d2s_group_observation *o) {
    return (o->evidence & (D2S_GROUP_DIRECT_CLEAR|D2S_GROUP_PLAN_FAILED|D2S_GROUP_SCOPE_DENY))!=0;
}
static uint64_t context_bit(const d2s_group_key *k) {
    return k->shape<32 ? UINT64_C(1) << (k->shape+(k->family==6?32:0)) : 0;
}
static int prohibited(const d2s_group_state *s,const char *suffix,const d2s_group_key *key) {
    if(s->blocked_contexts & context_bit(key))return 1;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2s_group_observation *o=&s->observations[i];
        if(o->evidence==D2S_GROUP_SCOPE_DENY && d2s_group_key_same(&o->key,key) &&
           (member(suffix,o->name)||member(o->name,suffix)))return 1;
    }
    return 0;
}
/* Compaction ONLY removes permission to generalize. No negative is forgotten:
 * first replace an exact negative by its registrable-domain prohibition;
 * if this cannot reclaim room, prohibit this protocol/family/shape entirely.
 * Path and ECH origins are widened only in the conservative fallback. */
static void compact_negative(d2s_group_state *s) {
    size_t victim=s->n_observations;char base[256]={0};
    for(size_t i=0;i<s->n_observations;i++)if(negative(&s->observations[i])) {
        if(victim==s->n_observations)victim=i;
        for(size_t j=i+1;j<s->n_observations;j++) {
            if(!negative(&s->observations[j]) ||
               !d2s_group_key_same(&s->observations[i].key,&s->observations[j].key))continue;
            const char *suffix=s->observations[i].name;
            while(suffix) {
                if(member(s->observations[j].name,suffix) && strlen(suffix)>strlen(base)) {
                    strcpy(base,suffix);victim=i;break;
                }
                suffix=strchr(suffix,'.');if(suffix)suffix++;
            }
        }
    }
    if(victim==s->n_observations)return;
    d2s_group_observation limit=s->observations[victim];
    /* No shared DNS suffix in this full context: the finite fallback widens
       only the prohibition, never permission. */
    if(!base[0])strcpy(base,limit.name);
    strcpy(limit.name,base);limit.plan_id[0]=0;limit.evidence=D2S_GROUP_SCOPE_DENY;
    size_t covered=0;
    for(size_t i=0;i<s->n_observations;i++)
        if(negative(&s->observations[i]) && d2s_group_key_same(&limit.key,&s->observations[i].key) &&
           member(s->observations[i].name,base))covered++;
    if(covered<2)s->blocked_contexts |= context_bit(&limit.key);
    for(size_t i=0;i<s->n_observations;) {
        const d2s_group_observation *o=&s->observations[i];
        int remove=negative(o) && (covered<2 ? context_bit(&o->key)==context_bit(&limit.key) :
            d2s_group_key_same(&o->key,&limit.key)&&member(o->name,base));
        if(remove)s->observations[i]=s->observations[--s->n_observations];else i++;
    }
    if(covered>=2)s->observations[s->n_observations++]=limit;
}
/* Live votes for the seed plan. A vote that later failed this plan or
   proved directly clear is stale: Р’В§3.7 returns a degraded family to the
   direct path instead of inheriting an unverified plan. */
static unsigned votes(const d2s_group_state *s,const char *suffix,
                       const d2s_group_observation *seed,int64_t *latest) {
    unsigned live=0,stale=0; *latest=0;
    if(prohibited(s,suffix,&seed->key))return 0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2s_group_observation *o=&s->observations[i];
        if(!d2s_group_key_same(&o->key,&seed->key) || !member(o->name,suffix)) continue;
        if((o->evidence&D2S_GROUP_DIRECT_CLEAR) &&
           !(o->evidence&D2S_GROUP_ADMITTED_EXCEPTION)) return 0;
        if((o->evidence&D2S_GROUP_BLOCKED_CONFIRMED) && strcmp(o->name,suffix) &&
           !strcmp(o->plan_id,seed->plan_id)) {
            if(o->evidence&(D2S_GROUP_PLAN_FAILED|D2S_GROUP_DIRECT_CLEAR)) { stale++; continue; }
            live++; if(o->at>*latest) *latest=o->at;
        }
    }
    return live>=2 && live>stale && live+stale>=3 ? live : 0;
}
static unsigned failures(const d2s_group_state *s,const char *suffix,
                         const d2s_group_key *key,const char *plan) {
    unsigned n=0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2s_group_observation *o=&s->observations[i];
        if((o->evidence&D2S_GROUP_PLAN_FAILED) &&
           d2s_group_key_same(&o->key,key) && member(o->name,suffix) &&
           !strcmp(o->plan_id,plan)) n++;
    }
    return n;
}
static void add_group(d2s_group_state *s,const char *suffix,
                      const d2s_group_observation *seed,unsigned count,int64_t at) {
    for(size_t i=0;i<s->n_groups;i++) {
        d2s_domain_group *g=&s->groups[i];
        if(!d2s_group_key_same(&g->key,&seed->key)) continue;
        if(!strcmp(g->suffix,suffix)) {
            /* Deterministic election, not catalog traversal order. */
            unsigned candidate_fail=failures(s,suffix,&seed->key,seed->plan_id);
            unsigned elected_fail=failures(s,suffix,&g->key,g->plan_id);
            if(candidate_fail<elected_fail || (candidate_fail==elected_fail &&
               (count>g->evidence_count || (count==g->evidence_count &&
               (at>g->at || (at==g->at && strcmp(seed->plan_id,g->plan_id)<0)))))) {
                strcpy(g->plan_id,seed->plan_id); g->evidence_count=count; g->at=at;
            }
            return;
        }
        if(!strcmp(g->plan_id,seed->plan_id) && member(suffix,g->suffix)) return;
    }
    for(size_t i=0;i<s->n_groups;) {
        d2s_domain_group *g=&s->groups[i];
        if(d2s_group_key_same(&g->key,&seed->key) &&
           !strcmp(g->plan_id,seed->plan_id) && member(g->suffix,suffix))
            s->groups[i]=s->groups[--s->n_groups];
        else i++;
    }
    if(s->n_groups==D2S_GROUP_MAX) return; /* area cap is not an admission stop */
    d2s_domain_group *g=&s->groups[s->n_groups++];
    memset(g,0,sizeof *g);
    strcpy(g->suffix,suffix); strcpy(g->plan_id,seed->plan_id);
    g->key=seed->key; g->evidence_count=count; g->at=at;
}
static void rebuild(d2s_group_state *s) {
    s->n_groups=0;
    if(s->disabled) return;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2s_group_observation *o=&s->observations[i];
        if(!(o->evidence&D2S_GROUP_BLOCKED_CONFIRMED)) continue;
        char base[256],best[256]={0};
        if(d2s_domain_base(o->name,base)) continue;
        const char *suffix=strchr(o->name,'.');
        unsigned best_count=0; int64_t best_at=0;
        while(suffix && strlen(++suffix)>=strlen(base)) {
            int64_t at=0; unsigned count=votes(s,suffix,o,&at);
            if(count) { strcpy(best,suffix); best_count=count; best_at=at; }
            suffix=strchr(suffix,'.');
        }
        if(best[0]) add_group(s,best,o,best_count,best_at);
    }
}
/* Group covering a normalized name, ignoring per-member exclusions. */
static const d2s_domain_group *cover(const d2s_group_state *s,const char *norm,
                                     const d2s_group_key *key) {
    const d2s_domain_group *best=NULL;
    if(s->disabled || s->n_groups>D2S_GROUP_MAX) return NULL;
    for(size_t i=0;i<s->n_groups;i++) {
        const d2s_domain_group *g=&s->groups[i];
        if(d2s_group_key_same(&g->key,key) && member(norm,g->suffix) &&
           (!best || strlen(g->suffix)>strlen(best->suffix))) best=g;
    }
    return best;
}
static int learn_exact(d2s_group_state *s,const d2s_group_observation *o) {
    char name[256],base[256];
    if(!s || !valid(o) || d2s_domain_normalize(o->name,name) ||
       d2s_domain_base(name,base) || s->n_groups>D2S_GROUP_MAX ||
       s->n_observations>D2S_GROUP_OBSERVATION_MAX) return -1;
    int admitted_clear=o->evidence==D2S_GROUP_DIRECT_CLEAR &&
        cover(s,name,&o->key)!=NULL;
    size_t slot=s->n_observations;
    size_t replace=s->n_observations,any=s->n_observations;
    for(size_t i=0;i<s->n_observations;i++)
        if(s->observations[i].evidence!=D2S_GROUP_SCOPE_DENY &&
           !strcmp(s->observations[i].name,name) &&
           d2s_group_key_same(&s->observations[i].key,&o->key)) {
            const d2s_group_observation *old=&s->observations[i];
            if(!strcmp(old->plan_id,o->plan_id)) { slot=i; break; }
            /* Prefer the same-plan entry: never leave two entries of one plan. */
            if((o->evidence==D2S_GROUP_DIRECT_CLEAR || o->evidence==D2S_GROUP_INCONCLUSIVE) &&
               any==s->n_observations) any=i;
            if(o->evidence==D2S_GROUP_BLOCKED_CONFIRMED &&
               !(old->evidence&D2S_GROUP_PLAN_FAILED) && replace==s->n_observations) replace=i;
        }
    if(slot==s->n_observations && any<s->n_observations) slot=any;
    if(slot==s->n_observations && replace<s->n_observations) slot=replace;
    if(slot==s->n_observations) {
        if(slot==D2S_GROUP_OBSERVATION_MAX)return -1;
        s->observations[slot]=*o;strcpy(s->observations[slot].name,name);
        s->n_observations++;
    } else {
        d2s_group_observation *old=&s->observations[slot];
        if(o->at<old->at || o->evidence==D2S_GROUP_INCONCLUSIVE) return 0;
        if(o->evidence==D2S_GROUP_DIRECT_CLEAR &&
           (old->evidence&D2S_GROUP_ADMITTED_EXCEPTION)) admitted_clear=1;
        /* Execution failure becomes an exception, not erasure of a historic
           successful vote: other group members keep their bypass. */
        if(o->evidence==D2S_GROUP_PLAN_FAILED) {
            if(strcmp(o->plan_id,old->plan_id)) return 0;
            old->evidence|=D2S_GROUP_PLAN_FAILED; old->at=o->at;
        } else if(admitted_clear && (old->evidence&D2S_GROUP_BLOCKED_CONFIRMED)) {
            old->evidence=D2S_GROUP_BLOCKED_CONFIRMED|D2S_GROUP_DIRECT_CLEAR|
                D2S_GROUP_ADMITTED_EXCEPTION;
            old->at=o->at; /* keep its historical own-plan vote for siblings */
        } else { *old=*o; strcpy(old->name,name); }
    }
    if(admitted_clear) s->observations[slot].evidence |= D2S_GROUP_ADMITTED_EXCEPTION;
    /* Keep one latest positive/clean observation per member, but preserve
       independent failed Plan IDs: trying B must not erase the failure of A. */
    if(o->evidence==D2S_GROUP_BLOCKED_CONFIRMED || o->evidence==D2S_GROUP_DIRECT_CLEAR)
        for(size_t i=0;i<s->n_observations;) {
            const d2s_group_observation *other=&s->observations[i];
            if(i!=slot && !strcmp(other->name,name) &&
               d2s_group_key_same(&other->key,&o->key) &&
               !(other->evidence&(D2S_GROUP_PLAN_FAILED|D2S_GROUP_SCOPE_DENY))) {
                size_t last=--s->n_observations;
                s->observations[i]=s->observations[last];
                if(slot==last) slot=i;
            } else i++;
        }
    if(o->evidence!=D2S_GROUP_INCONCLUSIVE) rebuild(s);
    return 1;
}
/* Two independent admission budgets in a compact shared storage view. The
 * view keeps existing exception/sync consumers exact; persistence splits it. */
int d2s_group_learn(d2s_group_state *s,const d2s_group_observation *o) {
    char norm[256],base[256];
    if(!s || !valid(o) || d2s_domain_normalize(o->name,norm) || d2s_domain_base(norm,base) ||
       s->n_observations>D2S_GROUP_OBSERVATION_MAX)return -1;
    if(o->evidence==D2S_GROUP_INCONCLUSIVE)return 0; /* not a learning vote */
    int neg=o->evidence==D2S_GROUP_DIRECT_CLEAR || o->evidence==D2S_GROUP_PLAN_FAILED;
    if(neg && prohibited(s,norm,&o->key))return 0;
    size_t count=0,oldest=s->n_observations;
    for(size_t i=0;i<s->n_observations;i++)if(negative(&s->observations[i])==neg) {
        count++;
        if(oldest==s->n_observations || s->observations[i].at<s->observations[oldest].at)oldest=i;
    }
    /* Replacing our own same-key record does not require another slot. */
    int existing=0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2s_group_observation *v=&s->observations[i];
        if(!strcmp(v->name,norm)&&d2s_group_key_same(&v->key,&o->key) && negative(v)==neg &&
           (!neg || o->evidence==D2S_GROUP_DIRECT_CLEAR || !strcmp(v->plan_id,o->plan_id)))existing=1;
    }
    int compacted=0;
    if(!existing && count >= (neg?D2S_GROUP_NEGATIVE_MAX:D2S_GROUP_POSITIVE_MAX)) {
        compacted=1;
        if(neg)compact_negative(s);
        else { memmove(&s->observations[oldest],&s->observations[oldest+1],
            (s->n_observations-oldest-1)*sizeof s->observations[0]);s->n_observations--; }
    }
    if(s->disabled)s->blocked_contexts=UINT64_MAX;
    s->frozen=0;s->disabled=0;s->journal_version=2;
    if(neg && prohibited(s,norm,&o->key)){rebuild(s);return 1;}
    int changed=learn_exact(s,o);
    /* A positive may become negative or vice versa on update. Enforce quotas
       after the event too; compaction may conservatively withdraw an area. */
    for(;;) {
        size_t n=0;for(size_t i=0;i<s->n_observations;i++)n+=negative(&s->observations[i]);
        if(n<=D2S_GROUP_NEGATIVE_MAX)break;
        compact_negative(s);
    }
    for(;;) {
        size_t n=0,v=s->n_observations;
        for(size_t i=0;i<s->n_observations;i++)if(!negative(&s->observations[i])) {
            n++;if(v==s->n_observations || s->observations[i].at<s->observations[v].at)v=i;
        }
        if(n<=D2S_GROUP_POSITIVE_MAX)break;
        s->observations[v]=s->observations[--s->n_observations];
    }
    rebuild(s);s->frozen=0;return changed<0?changed:(changed||compacted);
}
int d2s_group_restore(d2s_group_state *s) {
    if(!s || s->n_observations>D2S_GROUP_OBSERVATION_MAX || s->disabled_at<0) return -1;
    for(size_t i=0;i<s->n_observations;i++) {
        d2s_group_observation *o=&s->observations[i], test=*o;
        /* learn() writes masks; reduce them to the raw events they came from. */
        /* A failure may be ORed onto a stored INCONCLUSIVE; the failure stays. */
        if(test.evidence!=D2S_GROUP_INCONCLUSIVE) test.evidence&=~D2S_GROUP_INCONCLUSIVE;
        if(test.evidence&D2S_GROUP_ADMITTED_EXCEPTION) {
            if(!(test.evidence&D2S_GROUP_DIRECT_CLEAR)) return -1;
            test.evidence&=~D2S_GROUP_ADMITTED_EXCEPTION;
        }
        if(test.evidence&D2S_GROUP_BLOCKED_CONFIRMED)
            test.evidence&=~(D2S_GROUP_DIRECT_CLEAR|D2S_GROUP_PLAN_FAILED);
        else if((test.evidence&D2S_GROUP_DIRECT_CLEAR) &&
                (test.evidence&D2S_GROUP_PLAN_FAILED))
            test.evidence=D2S_GROUP_PLAN_FAILED;
        char norm[256],base[256];
        if(test.evidence==D2S_GROUP_SCOPE_DENY)test.evidence=D2S_GROUP_DIRECT_CLEAR;
        if(!valid(&test) || o->at<0 || d2s_domain_normalize(o->name,norm) ||
           (o->evidence!=D2S_GROUP_SCOPE_DENY && d2s_domain_base(norm,base))) return -1;
        strcpy(o->name,norm);
        for(size_t j=0;j<i;j++)
            if(s->observations[j].evidence!=D2S_GROUP_SCOPE_DENY && o->evidence!=D2S_GROUP_SCOPE_DENY &&
               !strcmp(s->observations[j].name,o->name) &&
               d2s_group_key_same(&s->observations[j].key,&o->key) &&
               (!strcmp(s->observations[j].plan_id,o->plan_id) ||
                !((s->observations[j].evidence|o->evidence)&D2S_GROUP_PLAN_FAILED))) return -1;
    }
    size_t neg=0;
    for(size_t i=0;i<s->n_observations;i++)neg+=negative(&s->observations[i]);
    if(neg>D2S_GROUP_NEGATIVE_MAX || s->n_observations-neg>D2S_GROUP_POSITIVE_MAX)return -1;
    /* Lost legacy exclusions have no known scope. Preserve a conservative
       barrier unless an explicit, backed-up new epoch is authorized. */
    if(s->disabled)s->blocked_contexts=UINT64_MAX;
    s->journal_version=2;s->disabled=0;s->frozen=0;
    rebuild(s);return 0;
}
const d2s_domain_group *d2s_group_match(const d2s_group_state *s,
                                     const char *name,const d2s_group_key *key) {
    char norm[256];
    if(!s || s->disabled || !key || d2s_domain_normalize(name,norm) ||
       s->n_groups>D2S_GROUP_MAX || s->n_observations>D2S_GROUP_OBSERVATION_MAX) return NULL;
    const d2s_domain_group *best=NULL;
    for(size_t i=0;i<s->n_groups;i++) {
        const d2s_domain_group *g=&s->groups[i];
        if(!d2s_group_key_same(&g->key,key) || !member(norm,g->suffix)) continue;
        int excluded=0;
        for(size_t j=0;j<s->n_observations;j++) {
            const d2s_group_observation *o=&s->observations[j];
            if(strcmp(o->name,norm) || !d2s_group_key_same(&o->key,key)) continue;
            if((o->evidence&D2S_GROUP_DIRECT_CLEAR) ||
               ((o->evidence&D2S_GROUP_PLAN_FAILED) && !strcmp(o->plan_id,g->plan_id))) excluded=1;
        }
        if(!excluded && (!best || strlen(g->suffix)>strlen(best->suffix))) best=g;
    }
    return best;
}
int d2s_group_forget(d2s_group_state *s,const char *name,uint8_t transport,uint8_t family) {
    char norm[256];
    if(!s || !name || d2s_domain_normalize(name,norm) ||
       s->n_observations>D2S_GROUP_OBSERVATION_MAX) return 0;
    int dropped=0;
    for(size_t i=0;i<s->n_observations;) {
        const d2s_group_observation *o=&s->observations[i];
        if(!strcmp(o->name,norm) && o->key.transport==transport && o->key.family==family &&
           (o->evidence&D2S_GROUP_PLAN_FAILED)) {
            s->observations[i]=s->observations[--s->n_observations];
            memset(&s->observations[s->n_observations],0,sizeof s->observations[0]);
            dropped++;
        } else i++;
    }
    if(dropped) rebuild(s);
    return dropped;
}
int d2s_group_expire(d2s_group_state *s,int64_t now,int64_t max_age) {
    if(!s || max_age<=0 || now<max_age || s->n_observations>D2S_GROUP_OBSERVATION_MAX) return 0;
    int dropped=0;
    for(size_t i=0;i<s->n_observations;) {
        const d2s_group_observation *o=&s->observations[i];
        if((o->evidence&D2S_GROUP_PLAN_FAILED) && o->at<now-max_age) {
            s->observations[i]=s->observations[--s->n_observations];
            memset(&s->observations[s->n_observations],0,sizeof s->observations[0]);
            dropped++;
        } else i++;
    }
    if(dropped) rebuild(s);
    return dropped;
}
