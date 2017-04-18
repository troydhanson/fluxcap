#include "cc-internal.h"

const UT_mm ptr_mm = { .sz = sizeof(void*) };

static void cc_init(void *_cc) {
  struct cc *cc = (struct cc*)_cc;
  utvector_init(&cc->names,        utstring_mm);
  utvector_init(&cc->output_types, utmm_int);
  utvector_init(&cc->defaults,     utstring_mm);
  utvector_init(&cc->caller_addrs, &ptr_mm);
  utvector_init(&cc->caller_types, utmm_int);
  utstring_init(&cc->flat);
  utstring_init(&cc->tmp);
}
static void cc_fini(void *_cc) {
  struct cc *cc = (struct cc*)_cc;
  utvector_fini(&cc->names);
  utvector_fini(&cc->output_types);
  utvector_fini(&cc->defaults);
  utvector_fini(&cc->caller_addrs);
  utvector_fini(&cc->caller_types);
  utstring_done(&cc->flat);
  utstring_done(&cc->tmp);
}
static void cc_copy(void *_dst, void *_src) {
  struct cc *dst = (struct cc*)_dst;
  struct cc *src = (struct cc*)_src;
  //utmm_copy(utvector_mm, &dst->names, &src->names, 1);
  //utmm_copy(utvector_mm, &dst->output_types, &src->output_types, 1);
  //utmm_copy(utvector_mm, &dst->defaults, &src->defaults, 1);
  //utmm_copy(utvector_mm, &dst->caller_addrs, &src->caller_addrs, 1);
  //utmm_copy(utvector_mm, &dst->caller_types, &src->caller_types, 1);
  //utmm_copy(utstring_mm, &dst->flat, &src->flat, 1);
  //utmm_copy(utstring_mm, &dst->tmp, &src->tmp, 1);
  utvector_copy(&dst->names,       &src->names);
  utvector_copy(&dst->output_types,&src->output_types);
  utvector_copy(&dst->defaults,    &src->defaults);
  utvector_copy(&dst->caller_addrs,&src->caller_addrs);
  utvector_copy(&dst->caller_types,&src->caller_types);
  utstring_bincpy(&dst->flat,utstring_body(&src->flat),utstring_len(&src->flat));
  utstring_bincpy(&dst->tmp,utstring_body(&src->tmp),utstring_len(&src->tmp));
}
static void cc_clear(void *_cc) {
  struct cc *cc = (struct cc*)_cc;
  utvector_clear(&cc->names);
  utvector_clear(&cc->output_types);
  utvector_clear(&cc->defaults);
  utvector_clear(&cc->caller_addrs);
  utvector_clear(&cc->caller_types);
  utstring_clear(&cc->flat);
  utstring_clear(&cc->tmp);
}

UT_mm const cc_mm = {
  .sz = sizeof(struct cc),
  .init = cc_init,
  .fini = cc_fini,
  .copy = cc_copy,
  .clear = cc_clear,
};

static int xcpf_i16_i16(UT_string *d, void *p) {
  utstring_bincpy(d, p, sizeof(int16_t));
  return 0;
}

static int xcpf_i16_i32(UT_string *d, void *p) {
  int16_t i16 = *(int16_t*)p;
  int32_t i32 = i16;
  utstring_bincpy(d, &i32, sizeof(i32));
  return 0;
}

static int xcpf_i16_str(UT_string *d, void *p) {
  int16_t i16 = *(int16_t*)p;
  int i = i16;
  char s[10];
  snprintf(s, sizeof(s), "%d", i);
  uint32_t l = strlen(s);
  utstring_bincpy(d, &l, sizeof(l));
  utstring_bincpy(d, s, l);
  return 0;
}

static int xcpf_i16_d64(UT_string *d, void *p) {
  int16_t i16 = *(int16_t*)p;
  double f = i16;
  utstring_bincpy(d, &f, sizeof(f));
  return 0;
}

static int xcpf_i32_i32(UT_string *d, void *p) {
  utstring_bincpy(d, p, sizeof(int32_t));
  return 0;
}

static int xcpf_i32_ipv4(UT_string *d, void *p) {
  utstring_bincpy(d, p, sizeof(int32_t));
  return 0;
}

static int xcpf_i32_str(UT_string *d, void *p) {
  int32_t i32 = *(int32_t*)p;
  int i = i32;
  char s[20];
  snprintf(s, sizeof(s), "%d", i);
  uint32_t l = strlen(s);
  utstring_bincpy(d, &l, sizeof(l));
  utstring_bincpy(d, s, l);
  return 0;
}

static int xcpf_i32_d64(UT_string *d, void *p) {
  int32_t i32 = *(int32_t*)p;
  double f = i32;
  utstring_bincpy(d, &f, sizeof(f));
  return 0;
}

static int xcpf_ipv4_i32(UT_string *d, void *p) {
  utstring_bincpy(d, p, sizeof(int32_t));
  return 0;
}

static int xcpf_ipv4_ipv4(UT_string *d, void *p) {
  utstring_bincpy(d, p, sizeof(int32_t));
  return 0;
}

static int xcpf_ipv4_str(UT_string *d, void *p) {
  uint32_t u32 = *(uint32_t*)p;
  uint8_t ia, ib, ic, id;
  char s[20];
  ia = (u32 & 0xff000000) >> 24;
  ib = (u32 & 0x00ff0000) >> 16;
  ic = (u32 & 0x0000ff00) >>  8;
  id = (u32 & 0x000000ff) >>  0;
  snprintf(s, sizeof(s), "%d.%d.%d.%d.", (int)ia, (int)ib, (int)ic, (int)id);
  uint32_t l = strlen(s);
  utstring_bincpy(d, &l, sizeof(l));
  utstring_bincpy(d, s, l);
  return 0;
}

static int xcpf_str_i16(UT_string *d, void *p) {
  char **c = (char **)p;
  int i;
  if (sscanf(*c, "%d", &i) != 1) return -1;
  int16_t i16 = i; // may truncate
  utstring_bincpy(d, &i16, sizeof(i16));
  return 0;
}

static int xcpf_str_i32(UT_string *d, void *p) {
  char **c = (char **)p;
  int i;
  if (sscanf(*c, "%d", &i) != 1) return -1;
  int32_t i32 = i;
  utstring_bincpy(d, &i32, sizeof(i32));
  return 0;
}

static int xcpf_str_ipv4(UT_string *d, void *p) {
  char **s = (char **)p;
  int ia, ib, ic, id;
  uint32_t ip;
  if (sscanf(*s, "%d.%d.%d.%d", &ia, &ib, &ic, &id) != 4) return -1;
  if ((ia > 255) || (ib > 255) || (ic > 255) || (id > 255)) return -1;
  ip = (ia << 24) | (ib << 16) || (ic << 8) | id;
  utstring_bincpy(d, &ip, sizeof(ip));
  return 0;
}

static int xcpf_str_str(UT_string *d, void *p) {
  char **c = (char **)p;
  uint32_t l = strlen(*c);
  utstring_bincpy(d, &l, sizeof(l));
  if (l) utstring_printf(d, "%s", *c);
  return 0;
}

static int xcpf_str_i8(UT_string *d, void *p) {
  char **c = (char **)p;
  int i;
  if (sscanf(*c, "%d", &i) != 1) return -1;
  int8_t i8 = i; // may truncate
  utstring_bincpy(d, &i8, sizeof(i8));
  return 0;
}

static int xcpf_str_d64(UT_string *d, void *p) {
  char **c = (char **)p;
  double f;
  if (sscanf(*c, "%lf", &f) != 1) return -1;
  utstring_bincpy(d, &f, sizeof(f));
  return 0;
}

static int xcpf_str_mac(UT_string *d, void *p) {
  char **c = (char **)p;
  unsigned int ma, mb, mc, md, me, mf;
  if (sscanf(*c, "%x:%x:%x:%x:%x:%x", &ma,&mb,&mc,&md,&me,&mf) != 1) return -1;
  if ((ma > 255) || (mb > 255) || (mc > 255) || 
      (md > 255) || (me > 255) || (mf > 255)) return -1;
  utstring_printf(d, "%c%c%c%c%c%c", ma, mb, mc, md, me, mf);
  return 0;
}

static int xcpf_i8_i16(UT_string *d, void *p) {
  int8_t i8 = *(int8_t*)p;
  int16_t i16 = i8;
  utstring_bincpy(d, &i16, sizeof(i16));
  return 0;
}

static int xcpf_i8_i32(UT_string *d, void *p) {
  int8_t i8 = *(int8_t*)p;
  int32_t i32 = i8;
  utstring_bincpy(d, &i32, sizeof(i32));
  return 0;
}

static int xcpf_i8_str(UT_string *d, void *p) {
  int8_t i8 = *(int8_t*)p;
  int i = i8;
  char s[5];
  snprintf(s, sizeof(s), "%d", i);
  uint32_t l = strlen(s);
  utstring_bincpy(d, &l, sizeof(l));
  utstring_bincpy(d, s, l);
  return 0;
}

static int xcpf_i8_i8(UT_string *d, void *p) {
  utstring_bincpy(d, p, sizeof(int8_t));
  return 0;
}

static int xcpf_i8_d64(UT_string *d, void *p) {
  int8_t i8 = *(int8_t*)p;
  double f = i8;
  utstring_bincpy(d, &f, sizeof(f));
  return 0;
}

static int xcpf_d64_i16(UT_string *d, void *p) {
  double f = *(double*)p;
  int16_t i16 = f;
  utstring_bincpy(d, &i16, sizeof(i16));
  return 0;
}

static int xcpf_d64_i32(UT_string *d, void *p) {
  double f = *(double*)p;
  int32_t i32 = f;
  utstring_bincpy(d, &i32, sizeof(i32));
  return 0;
}

static int xcpf_d64_str(UT_string *d, void *p) {
  double f = *(double*)p;
  char s[40];
  snprintf(s, sizeof(s), "%f", f);
  uint32_t l = strlen(s);
  utstring_bincpy(d, &l, sizeof(l));
  utstring_bincpy(d, s, l);
  return 0;
}

static int xcpf_d64_i8(UT_string *d, void *p) {
  double f = *(double*)p;
  int8_t i8 = f;
  utstring_bincpy(d, &i8, sizeof(i8));
  return 0;
}

static int xcpf_d64_d64(UT_string *d, void *p) {
  utstring_bincpy(d, p, sizeof(double));
  return 0;
}

static int xcpf_mac_str(UT_string *d, void *p) {
  unsigned char *m = p;
  char s[20];
  snprintf(s, sizeof(s), "%x:%x:%x:%x:%x:%x", (int)m[0], (int)m[1], (int)m[2],  
                                          (int)m[3], (int)m[4], (int)m[5]);
  uint32_t l = strlen(s);
  utstring_bincpy(d, &l, sizeof(l));
  utstring_bincpy(d, s, l);
  return 0;
}

static int xcpf_mac_mac(UT_string *d, void *p) {
  utstring_bincpy(d, p, 6*sizeof(char));
  return 0;
}


xcpf cc_conversions[/*from*/NUM_TYPES][/*to*/NUM_TYPES] = {
  [CC_i16][CC_i16] = xcpf_i16_i16,
  [CC_i16][CC_i32] = xcpf_i16_i32,
  [CC_i16][CC_ipv4] = NULL,
  [CC_i16][CC_str] = xcpf_i16_str,
  [CC_i16][CC_i8] = NULL,
  [CC_i16][CC_d64] = xcpf_i16_d64,
  [CC_i16][CC_mac] = NULL,

  [CC_i32][CC_i16] = NULL,
  [CC_i32][CC_i32] = xcpf_i32_i32,
  [CC_i32][CC_ipv4] = xcpf_i32_ipv4,
  [CC_i32][CC_str] = xcpf_i32_str,
  [CC_i32][CC_i8] = NULL,
  [CC_i32][CC_d64] = xcpf_i32_d64,
  [CC_i32][CC_mac] = NULL,

  [CC_ipv4][CC_i16] = NULL,
  [CC_ipv4][CC_i32] = xcpf_ipv4_i32,
  [CC_ipv4][CC_ipv4] = xcpf_ipv4_ipv4,
  [CC_ipv4][CC_str] = xcpf_ipv4_str,
  [CC_ipv4][CC_i8] = NULL,
  [CC_ipv4][CC_d64] = NULL,
  [CC_ipv4][CC_mac] = NULL,

  [CC_str][CC_i16] = xcpf_str_i16,
  [CC_str][CC_i32] = xcpf_str_i32,
  [CC_str][CC_ipv4] = xcpf_str_ipv4,
  [CC_str][CC_str] = xcpf_str_str,
  [CC_str][CC_i8] = xcpf_str_i8,
  [CC_str][CC_d64] = xcpf_str_d64,
  [CC_str][CC_mac] = xcpf_str_mac,

  [CC_i8][CC_i16] = xcpf_i8_i16,
  [CC_i8][CC_i32] = xcpf_i8_i32,
  [CC_i8][CC_ipv4] = NULL,
  [CC_i8][CC_str] = xcpf_i8_str,
  [CC_i8][CC_i8] = xcpf_i8_i8,
  [CC_i8][CC_d64] = xcpf_i8_d64,
  [CC_i8][CC_mac] = NULL,

  [CC_d64][CC_i16] = xcpf_d64_i16,
  [CC_d64][CC_i32] = xcpf_d64_i32,
  [CC_d64][CC_ipv4] = NULL,
  [CC_d64][CC_str] = xcpf_d64_str,
  [CC_d64][CC_i8] = xcpf_d64_i8,
  [CC_d64][CC_d64] = xcpf_d64_d64,
  [CC_d64][CC_mac] = NULL,

  [CC_mac][CC_i16] = NULL,
  [CC_mac][CC_i32] = NULL,
  [CC_mac][CC_ipv4] = NULL,
  [CC_mac][CC_str] = xcpf_mac_str,
  [CC_mac][CC_i8] = NULL,
  [CC_mac][CC_d64] = NULL,
  [CC_mac][CC_mac] = xcpf_mac_mac,
};

