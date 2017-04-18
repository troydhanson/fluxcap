#ifndef __CC_INTERNAL_H__
#define __CC_INTERNAL_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include "libut.h"
#include "cc.h"

#define adim(a) (sizeof(a)/sizeof(*a))

struct cc {
  UT_vector /* of UT_string */ names;
  UT_vector /* of int       */ output_types; /* enum (CC_i16 CC_i32) etc */
  UT_vector /* of UT_string */ defaults;     /* pack w/o map uses this default */
  UT_vector /* of void* */     caller_addrs; /* caller pointer to copy data from */
  UT_vector /* of int       */ caller_types; /* caller pointer type i16 i32 etc */
  UT_string flat;                            /* concatenated packed values buffer */
  UT_string tmp;
};

const UT_mm ptr_mm;
const UT_mm const cc_mm;

#define x(t) #t,
static char *cc_types[] = { TYPES };
#undef x
#define NUM_TYPES (adim(cc_types))

/* prototype of copy-conversion function */
typedef int (*xcpf)(UT_string *to, void *from);
xcpf cc_conversions[NUM_TYPES][NUM_TYPES];

#endif // _CC_INTERNAL_H__
