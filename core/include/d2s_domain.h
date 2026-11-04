#ifndef D2S_DOMAIN_H
#define D2S_DOMAIN_H
/* ASCII DNS wire names; IDNs arrive as A-labels, not raw Unicode. */
int d2s_domain_normalize(const char *name, char out[256]);
int d2s_domain_base(const char *name, char out[256]);
/* Includes suffix itself; refuses public/private suffixes and invalid names. */
int d2s_domain_member(const char *name, const char *suffix);
#endif
