/* test_quicsnap.c — пачка Initial-датаграмм клиента (задача 66).
 *
 * Поле 15.10.2026: Chrome с постквантовым key_share шлёт ClientHello двумя
 * Initial, и снимок из одной датаграммы — обрывок. Стенд двух датаграмм общий
 * с задачей 40 (test_quic_pq.h): имя лежит во ВТОРОЙ датаграмме, как у Chrome
 * с его перестановкой расширений.
 */
#include <stdio.h>
#include <string.h>

#include "d2s_quicsnap.h"
#include "d2s_quic.h"
#include "d2s_quicwire.h"
#include "test_quic_pq.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s (строка %d)\n", m, __LINE__); fails++; } } while (0)

static size_t versioned(const uint8_t *in,size_t n,uint8_t *out,uint32_t version) {
    d2s_qw_hdr h;d2s_qw_keys k;uint8_t secret[32],plain[1500],hdr[256];
    size_t plen=0;uint64_t pn=0;
    if(d2s_qw_hdr_parse(in,n,0,&h) ||
       d2s_qw_initial_secret(h.version,in+h.dcid_off,h.dcid_len,D2S_QW_CLIENT,secret) ||
       d2s_qw_keys_from_secret(h.version,secret,&k) || d2s_qw_open(&k,&h,in,0,plain,&plen,&pn))return 0;
    size_t pnlen=h.length_claimed-plen-16;
    if(d2s_qw_initial_secret(version,in+h.dcid_off,h.dcid_len,D2S_QW_CLIENT,secret) ||
       d2s_qw_keys_from_secret(version,secret,&k))return 0;
    size_t hl=d2s_qw_long_hdr(hdr,sizeof hdr,version,D2S_QW_LT_INITIAL,
        in+h.dcid_off,h.dcid_len,in+h.scid_off,h.scid_len,pnlen,plen);
    return hl?d2s_qw_seal(&k,1,hdr,hl,pn,pnlen,plain,plen,out,1500):0;
}

int main(void) {
    uint8_t d1[1500], d2[1500];
    size_t l1 = 0, l2 = 0;
    CHECK(d2s_test_pq_initials("rutracker.org", d1, &l1, d2, &l2) == 0, "стенд двух датаграмм");
    const uint8_t *dg[2] = {d1, d2};
    size_t len[2] = {l1, l2};

    /* Whole-flight split: SNI in the second datagram cannot be located by
       the old datagram-local path, but the real CRYPTO stream is complete. */
    {
        size_t head=77,cut=77,rn=0,chl0=0,chl1=0;
        uint8_t re[1500],ch0[8192],ch1[8192];
        CHECK(d2s_quic_initial_split_crypto(d2,l2,re,sizeof re,&rn)!=0,"old local path unexpectedly had complete SNI context");
        CHECK(!d2s_quic_split_flight_prepare(dg,len,2,&head,&cut) && head==1 && cut>0,"whole flight did not find the second datagram");
        CHECK(!d2s_quic_initial_split_crypto_at(d2,l2,cut,re,sizeof re,&rn) && rn==l2,"selected Initial not transformed");
        const uint8_t *changed[]={re,d1};size_t cl[]={rn,l1};
        CHECK(!d2s_quic_dgrams_hello(dg,len,2,ch0,sizeof ch0,&chl0) &&
              !d2s_quic_dgrams_hello(changed,cl,2,ch1,sizeof ch1,&chl1) &&
              chl0==chl1 && !memcmp(ch0,ch1,chl0),"whole-flight split changed handshake bytes");
        d2s_qw_hdr a,b;CHECK(!d2s_qw_hdr_parse(d2,l2,0,&a) && !d2s_qw_hdr_parse(re,rn,0,&b) &&
            a.pn_offset==b.pn_offset && !memcmp(d2+1,re+1,a.pn_offset-1),"public header/DCID/token/length changed");
        const uint8_t *reversed[]={d2,d1};size_t reversed_len[]={l2,l1};
        CHECK(!d2s_quic_split_flight_prepare(reversed,reversed_len,2,&head,&cut) && head==0,"out-of-order flight refused");
        const uint8_t *duplicate[]={d1,d1};size_t dl[]={l1,l1};head=cut=77;
        CHECK(d2s_quic_split_flight_prepare(duplicate,dl,2,&head,&cut)!=0 && head==77 && cut==77,"duplicate PN/overlap accepted or partial output committed");
        CHECK(d2s_quic_split_flight_prepare(dg,len,1,&head,&cut)!=0,"incomplete flight accepted");
        uint8_t bad[1500];memcpy(bad,d2,l2);bad[l2-1]^=1;
        const uint8_t *broken[]={d1,bad};
        CHECK(d2s_quic_split_flight_prepare(broken,len,2,&head,&cut)!=0,"bad AEAD tag accepted");
        bad[6]^=1;
        CHECK(d2s_quic_split_flight_prepare(broken,len,2,&head,&cut)!=0,"mixed connection accepted");
        uint8_t v2a[1500],v2b[1500];size_t v2len[]={versioned(d1,l1,v2a,D2S_QW_V2),versioned(d2,l2,v2b,D2S_QW_V2)};
        const uint8_t *v2[]={v2a,v2b};
        CHECK(v2len[0]==l1 && v2len[1]==l2 &&
              !d2s_quic_split_flight_prepare(v2,v2len,2,&head,&cut) && head==1,"QUIC v2 whole flight failed");
        CHECK(!d2s_quic_initial_split_crypto_at(v2b,v2len[1],cut,re,sizeof re,&rn),"QUIC v2 selected packet failed");
        const uint8_t *v2changed[]={v2a,re};size_t v2cl[]={v2len[0],rn};
        CHECK(!d2s_quic_dgrams_hello(v2changed,v2cl,2,ch1,sizeof ch1,&chl1) &&
              chl1==chl0 && !memcmp(ch0,ch1,chl0),"QUIC v2 handshake changed");
        const uint8_t *mixed[]={d1,v2b};
        CHECK(d2s_quic_split_flight_prepare(mixed,len,2,&head,&cut)!=0,"mixed QUIC versions accepted");
        uint8_t coalesced[1500],tail[256],body[20]={1},hdr[128],sec[32];
        d2s_qw_hdr source;d2s_qw_keys keys;
        CHECK(!d2s_qw_hdr_parse(d2,l2,0,&source) &&
              !d2s_qw_initial_secret(source.version,d2+source.dcid_off,source.dcid_len,D2S_QW_CLIENT,sec) &&
              !d2s_qw_keys_from_secret(source.version,sec,&keys),"coalesced fixture keys");
        size_t hl=d2s_qw_long_hdr(hdr,sizeof hdr,source.version,D2S_QW_LT_0RTT,
            d2+source.dcid_off,source.dcid_len,d2+source.scid_off,source.scid_len,4,sizeof body);
        size_t tn=d2s_qw_seal(&keys,1,hdr,hl,3,4,body,sizeof body,tail,sizeof tail);
        CHECK(tn && l2+tn<=sizeof coalesced,"coalesced fixture size");
        memcpy(coalesced,d2,l2);memcpy(coalesced+l2,tail,tn);
        const uint8_t *coal[]={d1,coalesced};size_t coal_len[]={l1,l2+tn};
        CHECK(!d2s_quic_split_flight_prepare(coal,coal_len,2,&head,&cut) && head==1 &&
              !d2s_quic_initial_split_crypto_at(coalesced,l2+tn,cut,re,sizeof re,&rn) &&
              rn==l2+tn && !memcmp(re+l2,tail,tn),"coalesced opaque tail changed");
        /* Fill the target Initial almost completely with CRYPTO. There is
           insufficient PADDING for another frame header: refuse atomically. */
        uint8_t longch[2200];size_t old=d2s_test_pq_hello(longch,sizeof longch,"rutracker.org");
        size_t total=2149,added=total-old;
        CHECK(old && added>=4,"long CH fixture");
        longch[1]=(uint8_t)((total-4)>>16);longch[2]=(uint8_t)((total-4)>>8);longch[3]=(uint8_t)(total-4);
        size_t exts=((size_t)longch[45]<<8 | longch[46])+added;
        longch[45]=(uint8_t)(exts>>8);longch[46]=(uint8_t)exts;
        longch[old]=0;longch[old+1]=21;longch[old+2]=(uint8_t)((added-4)>>8);longch[old+3]=(uint8_t)(added-4);
        memset(longch+old+4,0,added-4);
        static const uint8_t cid[]={1,2,3,4,5,6,7,8};
        uint8_t fulla[1500],fullb[1500];
        size_t full_len[]={d2s_test_pq_dgram(cid,0,0,longch,1000,fulla,sizeof fulla),
            d2s_test_pq_dgram(cid,1,1000,longch+1000,total-1000,fullb,sizeof fullb)};
        const uint8_t *full[]={fulla,fullb};head=cut=77;
        CHECK(full_len[0] && full_len[1] && d2s_quic_split_flight_prepare(full,full_len,2,&head,&cut)!=0 &&
              head==77 && cut==77,"insufficient padding accepted/partial commit");
    }

    /* --- упаковка и разбор --------------------------------------------- */
    uint8_t blob[D2S_SHAPE_MAX];
    size_t bl = d2s_qsnap_pack(dg, len, 2, blob, sizeof blob);
    CHECK(bl == 4 + 2 + l1 + 2 + l2, "длина пачки: магия, число, по длине на датаграмму");
    CHECK(d2s_qsnap_is(blob, bl), "магия пачки не узнана");
    /* Одиночная датаграмма пачкой не притворяется: у длинного заголовка QUIC
       обязателен бит 0x80, и с 'Q' она начаться не может. */
    CHECK(!d2s_qsnap_is(d1, l1), "одиночная датаграмма принята за пачку");

    d2s_qsnap s;
    CHECK(d2s_qsnap_parse(blob, bl, &s) == 0, "разбор пачки");
    CHECK(s.n == 2 && s.len[0] == l1 && s.len[1] == l2, "число и длины датаграмм");
    CHECK(!memcmp(s.dg[0], d1, l1) && !memcmp(s.dg[1], d2, l2), "байты датаграмм не те");

    /* --- приветствие и имя ---------------------------------------------- */
    uint8_t ch[8192];
    size_t chl = 0;
    CHECK(d2s_quic_dgrams_hello(dg, len, 2, ch, sizeof ch, &chl) == 0,
          "ClientHello из двух датаграмм");
    CHECK(chl > 4 && ch[0] == 0x01, "собрано не ClientHello");
    CHECK(chl == 4 + ((size_t)ch[1] << 16 | (size_t)ch[2] << 8 | ch[3]),
          "собрано не до заявленной длины");

    uint8_t ch_s[8192];
    size_t ch_sl = 0;
    CHECK(d2s_qsnap_client_hello(&s, ch_s, sizeof ch_s, &ch_sl) == 0 &&
          ch_sl == chl && !memcmp(ch_s, ch, chl), "пачка даёт тот же ClientHello");

    char name[256];
    CHECK(d2s_qsnap_sni(&s, name, sizeof name) == 0 && !strcmp(name, "rutracker.org"),
          "имя из второй датаграммы");

    /* Первая датаграмма в одиночку — обрывок, а не приветствие. */
    d2s_qsnap one = s;
    one.n = 1;
    CHECK(d2s_qsnap_client_hello(&one, ch_s, sizeof ch_s, &ch_sl) != 0,
          "половина приветствия принята за целое");
    CHECK(d2s_qsnap_sni(&one, name, sizeof name) != 0, "имя выдумано из обрывка");

    /* --- перезапечатка --------------------------------------------------- */
    uint8_t re[D2S_SHAPE_MAX];
    size_t rl = 0;
    CHECK(d2s_qsnap_recid(&s, re, sizeof re, &rl) == 0, "перезапечатка пачки");
    CHECK(rl == bl, "перезапечатка изменила длину пачки");
    d2s_qsnap r;
    CHECK(d2s_qsnap_parse(re, rl, &r) == 0 && r.n == 2 &&
          r.len[0] == l1 && r.len[1] == l2, "перезапечатанное — та же форма");
    /* DCID лежит с 6-го байта длинного заголовка: 1 тип + 4 версия + 1 длина. */
    CHECK(memcmp(r.dg[0] + 6, s.dg[0] + 6, 8) != 0, "DCID не обновлён");
    CHECK(!memcmp(r.dg[0] + 6, r.dg[1] + 6, 8), "у датаграмм пачки разные DCID");
    uint8_t ch_r[8192];
    size_t ch_rl = 0;
    CHECK(d2s_qsnap_client_hello(&r, ch_r, sizeof ch_r, &ch_rl) == 0 &&
          ch_rl == chl && !memcmp(ch_r, ch, chl),
          "перезапечатанная пачка не раскрывается в тот же ClientHello");
    uint8_t re2[D2S_SHAPE_MAX];
    size_t rl2 = 0;
    CHECK(d2s_qsnap_recid(&s, re2, sizeof re2, &rl2) == 0 && rl2 == rl &&
          memcmp(re2, re, rl) != 0, "две перезапечатки дали один DCID");

    /* Сдвоенный Initial нельзя перезапечатать только наполовину. */
    {
        uint8_t combined[1500], second[256], body[20]={1}, secret[32];
        d2s_qw_hdr first; d2s_qw_keys keys;
        CHECK(d2s_qw_hdr_parse(d1,l1,0,&first)==0,"разбор исходного заголовка");
        CHECK(d2s_qw_initial_secret(first.version,d1+first.dcid_off,first.dcid_len,D2S_QW_CLIENT,secret)==0,"секрет ключа второго Initial");
        CHECK(d2s_qw_keys_from_secret(first.version,secret,&keys)==0,"ключи второго Initial");
        size_t hl=d2s_qw_long_hdr(second,sizeof second,first.version,D2S_QW_LT_INITIAL,
            d1+first.dcid_off,first.dcid_len,d1+first.scid_off,first.scid_len,4,sizeof body);
        size_t n2=d2s_qw_seal(&keys,1,second,hl,1,4,body,sizeof body,second,sizeof second);
        CHECK(n2>0 && l1+n2<=sizeof combined,"второй корректный Initial");
        memcpy(combined,d1,l1);memcpy(combined+l1,second,n2);
        d2s_qsnap coal={0};coal.n=1;coal.dg[0]=combined;coal.len[0]=l1+n2;
        size_t outlen=0;uint8_t output[D2S_SHAPE_MAX];
        int rc=d2s_qsnap_recid(&coal,output,sizeof output,&outlen);
        int coherent=0;
        if(rc==0) {
            d2s_qsnap parsed;d2s_qw_hdr a,b;
            CHECK(d2s_qsnap_parse(output,outlen,&parsed)==0,"разбор перезапечатанного снимка");
            CHECK(d2s_qw_hdr_parse(parsed.dg[0],parsed.len[0],0,&a)==0,"разбор первого пакета результата");
            CHECK(d2s_qw_hdr_parse(parsed.dg[0]+a.packet_len,parsed.len[0]-a.packet_len,0,&b)==0,"разбор второго пакета результата");
            coherent=a.dcid_len==b.dcid_len && !memcmp(parsed.dg[0]+a.dcid_off,parsed.dg[0]+a.packet_len+b.dcid_off,a.dcid_len);
            printf("склейка recid: код=%d, DCID совпадает=%d, второй пакет без изменений=%d\n",
                   rc,coherent,!memcmp(parsed.dg[0]+a.packet_len,second,n2));
        }
        CHECK(rc!=0 || coherent,"recid должен отклонить склейку или обновить все Initial");
    }

    /* --- 4-байтный varint длины (форма Chrome 150) ----------------------- */
    /* Chrome выделяет 4 байта под поле Length в Initial. d2s_qsnap_recid
       обязан сохранять ширину поля и длину датаграммы без сжатия varint. */
    d2s_qw_hdr h1;
    CHECK(d2s_qw_hdr_parse(d1, l1, 0, &h1) == 0, "разбор d1 для теста 4-байтного varint");
    uint8_t plain1[1500]; size_t plain1_len = 0; uint64_t pn1 = 0;
    uint8_t sec1[32]; d2s_qw_keys k1;
    CHECK(d2s_qw_initial_secret(h1.version, d1 + h1.dcid_off, h1.dcid_len, D2S_QW_CLIENT, sec1) == 0, "секрет для d1");
    CHECK(d2s_qw_keys_from_secret(h1.version, sec1, &k1) == 0, "ключи для d1");
    CHECK(d2s_qw_open(&k1, &h1, d1, 0, plain1, &plain1_len, &pn1) == 0, "открытие d1");
    size_t pn1_len = h1.length_claimed - plain1_len - 16;
    if (plain1_len > 2) {
        plain1_len -= 2;
        uint8_t d1_4w[1500];
        size_t hl_4w = d2s_qw_long_hdr_w(d1_4w, sizeof d1_4w, h1.version, D2S_QW_LT_INITIAL,
                                         d1 + h1.dcid_off, h1.dcid_len, d1 + h1.scid_off, h1.scid_len,
                                         pn1_len, plain1_len, 4);
        CHECK(hl_4w > 0, "сборка заголовка с 4-байтным varint длины");
        size_t sealed_4w = d2s_qw_seal(&k1, 1, d1_4w, hl_4w, pn1, pn1_len, plain1, plain1_len,
                                       d1_4w, sizeof d1_4w);
        CHECK(sealed_4w == l1, "длина запечатанного пакета с 4-байтным varint совпала с l1");
        d2s_qw_hdr h_test;
        CHECK(d2s_qw_hdr_parse(d1_4w, sealed_4w, 0, &h_test) == 0, "разбор пакета с 4-байтным varint");
        CHECK(h_test.length_width == 4, "длина определена как 4-байтный varint");
        const uint8_t *dg_4w[2] = {d1_4w, d2};
        size_t len_4w[2] = {sealed_4w, l2};
        uint8_t blob_4w[D2S_SHAPE_MAX];
        size_t bl_4w = d2s_qsnap_pack(dg_4w, len_4w, 2, blob_4w, sizeof blob_4w);
        CHECK(bl_4w > 0, "упаковка пачки с 4-байтным varint");
        d2s_qsnap s_4w;
        CHECK(d2s_qsnap_parse(blob_4w, bl_4w, &s_4w) == 0, "разбор пачки с 4-байтным varint");
        uint8_t re_4w[D2S_SHAPE_MAX]; size_t rl_4w = 0;
        CHECK(d2s_qsnap_recid(&s_4w, re_4w, sizeof re_4w, &rl_4w) == 0,
              "перезапечатка пачки с 4-байтным varint длины");
        CHECK(rl_4w == bl_4w, "перезапечатка пачки с 4-байтным varint сохранила точную длину");
    }

    /* --- форма ------------------------------------------------------------ */
    d2s_quic_form f;
    CHECK(d2s_qsnap_form(&s, &f) == 0 && f.n == 2 && f.dgram_len == (uint16_t)l1 &&
          f.ch_len == (uint16_t)chl, "форма пачки");

    /* --- отказы ----------------------------------------------------------- */
    /* Датаграммы разных соединений (Retry посреди полёта, чужой поток в
       кольце датапата) не склеиваются в одно приветствие. */
    const uint8_t *mdg[2] = {d1, r.dg[1]};
    uint8_t mixed[D2S_SHAPE_MAX];
    size_t ml = d2s_qsnap_pack(mdg, len, 2, mixed, sizeof mixed);
    d2s_qsnap m;
    CHECK(ml > 0 && d2s_qsnap_parse(mixed, ml, &m) == 0, "упаковка смешанной пачки");
    CHECK(d2s_qsnap_client_hello(&m, ch_s, sizeof ch_s, &ch_sl) != 0,
          "датаграммы разных DCID склеены в одно приветствие");
    CHECK(d2s_qsnap_recid(&m, re, sizeof re, &rl) != 0, "смешанная пачка перезапечатана");

    /* Любое усечение отвергается целиком, а не разбирается наполовину. */
    for (size_t k = 0; k < bl; k++) {
        d2s_qsnap t;
        CHECK(d2s_qsnap_parse(blob, k, &t) != 0, "усечённая пачка принята");
    }
    /* Лишние байты в хвосте — тоже отказ: это не та пачка, что слал клиент. */
    uint8_t longer[D2S_SHAPE_MAX];
    memcpy(longer, blob, bl);
    longer[bl] = 0;
    {
        d2s_qsnap t;
        CHECK(d2s_qsnap_parse(longer, bl + 1, &t) != 0, "пачка с хвостом принята");
    }

    /* Мусор нужной длины — не приветствие и не перезапечатывается. */
    uint8_t junk[64];
    memset(junk, 0x5a, sizeof junk);
    const uint8_t *jdg[1] = {junk};
    size_t jlen[1] = {sizeof junk};
    uint8_t jb[128];
    size_t jbl = d2s_qsnap_pack(jdg, jlen, 1, jb, sizeof jb);
    d2s_qsnap j;
    CHECK(jbl > 0 && d2s_qsnap_parse(jb, jbl, &j) == 0, "упаковка мусора");
    CHECK(d2s_qsnap_client_hello(&j, ch_s, sizeof ch_s, &ch_sl) != 0,
          "мусор принят за приветствие");
    CHECK(d2s_qsnap_recid(&j, re, sizeof re, &rl) != 0, "мусор перезапечатан");

    /* Пределы упаковки. */
    CHECK(d2s_qsnap_pack(dg, len, 0, blob, sizeof blob) == 0, "пустая пачка собрана");
    CHECK(d2s_qsnap_pack(dg, len, D2S_QSNAP_MAX_DGRAMS + 1, blob, sizeof blob) == 0,
          "пачка сверх предела собрана");
    CHECK(d2s_qsnap_pack(dg, len, 2, blob, 16) == 0, "пачка собрана в тесный буфер");

    if (fails) { printf("test_quicsnap: провалов %d\n", fails); return 1; }
    printf("test_quicsnap: все проверки прошли\n");
    return 0;
}
