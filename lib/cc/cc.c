#include "cc-internal.h"

static int parse_cc(struct cc *cc, char *file) {
  int rc = -1;
  char line[100], *label;
  FILE *f=NULL;
  char *sp,*nl,*def;
  unsigned t;

  if ( (f = fopen(file,"r")) == NULL) {
    fprintf(stderr,"can't open %s: %s\n", file, strerror(errno));
    goto done;
  }

  /* parse the type specifier, label and optional default */
  while (fgets(line,sizeof(line),f) != NULL) {

    sp = strchr(line,' '); if (!sp) continue;
    nl = strchr(line,'\n'); if (nl) *nl='\0';

    for(t=0; t<NUM_TYPES; t++) {
      if(!strncmp(cc_types[t],line,sp-line)) break;
    }

    if (t >= NUM_TYPES){
      fprintf(stderr,"unknown type %s\n",line); 
      goto done;
    }

    label = sp+1;
    sp = strchr(label,' ');
    if (sp) *sp = '\0';

    def = sp ? sp+1 : NULL;

    /* names */
    utstring_clear(&cc->tmp);
    utstring_printf(&cc->tmp,"%s", label);
    utvector_push(&cc->names, &cc->tmp);

    /* types */
    utvector_push(&cc->output_types, &t);

    /* defaults */
    utstring_clear(&cc->tmp);
    if (def) utstring_printf(&cc->tmp,"%s", def);
    utvector_push(&cc->defaults, &cc->tmp);

    /* maps */
    utvector_extend(&cc->caller_addrs);
    utvector_extend(&cc->caller_types);
  }

  rc = 0;

 done:
  if (f) fclose(f);
  return rc;
}

/* open the cc file describing the buffer format */

struct cc * cc_open( char *file, int flags, ...) {
  int rc = -1;

  struct cc *cc = calloc(1, sizeof(*cc));
  if (cc == NULL) { fprintf(stderr,"out of memory\n"); goto done; }

  utmm_init(&cc_mm,cc,1);
  if (parse_cc(cc, file) < 0) goto done;
  if (flags) goto done;

  rc = 0;

 done:

  if ((rc < 0) && cc) {
    utmm_fini(&cc_mm,cc,1);
    free(cc);
    cc = NULL;
  }

  return cc;
}

int cc_close(struct cc *cc) {
  utmm_fini(&cc_mm,cc,1);
  free(cc);
  return 0;
}

/* get the slot index for the field having given name */
static int get_index(struct cc *cc, char *name) {
  int i=0;
  UT_string *s = NULL;
  while ( (s = utvector_next(&cc->names, s))) {
    if (strcmp(name, utstring_body(s)) == 0) break;
    i++;
  }
  return s ? i : -1;
}

/* associate pointers into caller memory with cc fields */
int cc_mapv(struct cc *cc, struct cc_map *map, int count) {
  int rc=-1, i, n, nmapped=0;
  struct cc_map *m;
  cc_type *ot, *ct;
  void **mp;

  for(n=0; n < count; n++) {

    m = &map[n];

    i = get_index(cc,m->name);
    if (i < 0) {
      m->addr = NULL; /* ignore field; inform caller */
      continue;
    }

    mp = utvector_elt(&cc->caller_addrs, i);
    ot = utvector_elt(&cc->output_types, i);
    ct = utvector_elt(&cc->caller_types, i);

    *ct = m->type;
    *mp = m->addr;

    if (cc_conversions[*ct][*ot] == NULL) goto done;
    nmapped++;
  }

  rc = 0;

 done:
  return (rc < 0) ? rc : nmapped;
}

int cc_dump(struct cc *cc, char **out, size_t *len) {
  int rc = -1, i=0;
  UT_string *df, *fn;
  cc_type *ot, *ct, t;
  void **mp, *p;
  char *def, *n;
  uint32_t l=0;

  utstring_clear(&cc->flat);
  utstring_bincpy(&cc->flat, &l, sizeof(l)); /* reserve room for len prefix */

  *out = NULL;
  *len = 0;

  fn = NULL;
  while( (fn = utvector_next(&cc->names, fn))) {

    mp = utvector_elt(&cc->caller_addrs, i);
    ot = utvector_elt(&cc->output_types, i);
    ct = utvector_elt(&cc->caller_types, i);
    df = utvector_elt(&cc->defaults, i);
    i++;

    def = utstring_body(df);
    n = utstring_body(fn);
    t = *ct;
    p = *mp;

    if (p == NULL) { /* no caller pointer for this field */

      if (utstring_len(df) > 0) { /* use default */
        t = CC_str;
        p = &def;
      } else {
        fprintf(stderr, "required field absent: %s\n", n);
        goto done;
      }
    }

    xcpf fcn = cc_conversions[t][*ot];
    if ((fcn == NULL) || (fcn(&cc->flat, p) < 0)) {
      fprintf(stderr,"conversion error (%s)\n", n);
      goto done;
    }
  }

  *out = utstring_body(&cc->flat);
  *len = utstring_len(&cc->flat);
  l = *len - sizeof(l);
  memcpy(*out, &l, sizeof(l));

  rc = 0;

 done:
  return rc;
}

int cc_restore(struct cc *cc, char *flat, size_t len) {
  int rc = -1;

  rc = 0;

 done:
  return rc;
}

