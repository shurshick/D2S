#ifndef D2S_ADDR_H
#define D2S_ADDR_H
#include <stddef.h>
#include <stdint.h>
/* Network bytes; IPv4 uses bytes[0..3], with a zero tail. */
typedef struct { uint8_t family; uint8_t bytes[16]; } d2s_addr;
/* Literal addresses only. Failure leaves out unchanged; no DNS or scope IDs. */
int d2s_addr_parse(const char *text, d2s_addr *out);
size_t d2s_addr_text(const d2s_addr *addr, char *out, size_t cap);
int d2s_addr_equal(const d2s_addr *a, const d2s_addr *b);
#endif
