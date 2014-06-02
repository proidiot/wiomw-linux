#ifndef _WIOMW_RW3_H_
#define _WIOMW_RW3_H_

typedef struct _rw3_struct rw3_t;

void rw3_start_write(rw3_t lock);
void rw3_end_write(rw3_t lock);
void rw3_start_read(rw3_t lock);
void rw3_end_read(rw3_t lock);

#endif
