/* d2s_plantlv.h — человеческий текст плана в байты провода.
 *
 * d2s_compose выдаёт план ТЕКСТОМ (он же лежит в catalog.json и его же
 * показывает панель), а датапат принимает ТОЛЬКО байты TLV. Этот модуль —
 * единственный мост между ними на C-стороне; на Go-стороне ту же работу
 * делают internal/plan ParseText и MarshalTLV, и они здесь эталон.
 *
 * Текст — ЕДИНСТВЕННЫЙ источник: что записано в каталоге, то и едет на провод.
 * Второй сборщик TLV рядом с текстовым (соблазн научить d2s_compose выдавать
 * сразу обе формы) завёл бы две формы одного плана, и первое же расхождение
 * между ними означало бы, что записано одно, а исполняется другое — §2.5
 * запрещает ровно это.
 *
 * Неизвестная директива — ОТКАЗ с причиной, а не пропуск строки. */
#ifndef D2S_PLANTLV_H
#define D2S_PLANTLV_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* Потолок одного плана в байтах. Кадр управляющего сокета — 65536
 * (D2S_CTL_FRAME_MAX, datapath/include/d2s_ctl.h), и план в нём самое
 * большое, что ездит; под имя цели и заголовок команды оставлен запас. */
#define D2S_PLAN_TLV_MAX 65000

/* 0 — переведено, *out_len заполнено. -1 — отказ, причина в err (заполняется
 * ВСЕГДА и по-человечески: «не разобралось» без объяснения нечитаемо тому,
 * кто будет чинить). */
int d2s_plan_text_to_tlv(const char *text, uint8_t *out, size_t cap,
                         size_t *out_len, char *err, size_t errcap);

/* То же, но сразу в hex — в том виде, в каком план принимает
 * d2s_link_set_name (d2s_link.h). out обязан быть не короче 2*N+1, где N —
 * длина TLV; для плана предельного размера это 2*D2S_PLAN_TLV_MAX+1. */
int d2s_plan_text_to_hex(const char *text, char *out, size_t cap,
                         char *err, size_t errcap);

/* One strictly cheaper hypothesis, never evidence. cursor enumerates edits of
 * this exact source; 1=candidate, 0=no further edit, -1=invalid/OOM. Both source
 * and result use the ordinary parser. Payloads, fooling and input guards stay
 * intact. The caller must independently verify before replacing a binding. */
int d2s_plan_simplify_next(const char *text, size_t cursor, char *out, size_t cap,
                           size_t *next, char *err, size_t errcap);

#endif /* D2S_PLANTLV_H */
