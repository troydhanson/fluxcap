#ifndef _FLATNER_H_
#define _FLATNER_H_
#if defined __cplusplus
extern "C" {
#endif

#include <inttypes.h>

/*
 * this callback is provided by the caller.
 * its purpose is to locate the next data
 * item in the buffer of length len. by
 * next data item, it means the one after
 * the "current" item at offset *off having
 * size *sz. (note *off and *sz may be zero
 * e.g. on the first invocation). the item's
 * timestamp should be placed into *ts. the
 * off and sz are input/output parameters.
 *
 * return
 *  0 if buffer is exhausted (no item found)
 *  1 if an item is available at offset off
 * -1 if an error occurred e.g. bad input
 *
 */
typedef int (next_cb)(char *name, char *buf, size_t len, 
             uint64_t *off, size_t *sz, uint64_t *ts);

struct flatner;

/* API */
struct flatner *flatner_new(next_cb *cb);
int flatner_add(struct flatner *f, char *file);
int flatner_next(struct flatner *f, char **loc, size_t *len, int *mc);
void flatner_free(struct flatner *f);
void flatner_clamp(struct flatner *f, uint64_t min, uint64_t max);
void flatner_describe(struct flatner *f);

#if defined __cplusplus
}
#endif
#endif
