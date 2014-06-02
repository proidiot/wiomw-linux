#include <config.h>
#include "rw3.h"

struct _rw3_struct {
	unsigned int rcount;
	sem_t wait;
	sem_t access;
	sem_t rclock;
};

rw3_t new_rw3()
{
	rw3_t val = (rw3_t)malloc(sizeof(struct _rw3_struct));
	val->rcount = 0;
	sem_init(&val->wait, 0, 1);
	sem_init(&val->access, 0, 1);
	sem_init(&val->rclock, 0, 1);
	return val;
}

void destroy_rw3(rw3_t* val)
{
	sem_destroy(&(*val)->wait);
	sem_destroy(&(*val)->access);
	sem_destroy(&(*val)->rclock);
	free(*val);
	*val = NULL;
}

void rw3_start_write(rw3_t lock)
{
	sem_wait(&lock->wait);
	sem_wait(&lock->access);
	sem_post(&lock->wait);
}

void rw3_end_write(rw3_t lock)
{
	sem_post(&lock->access);
}

void rw3_start_read(rw3_t lock)
{
	int pcount = 0;
	sem_wait(&lock->wait);
	sem_wait(&lock->rclock);
	pcount = lock->rcount;
	lock->rcount += 1;
	sem_post(&lock->rclock);
	if (pcount == 0) {
		sem_wait(&lock->access);
	}
	sem_post(&lock->wait);
}

void rw3_end_read(rw3_t lock)
{
	int ncount = 0;
	sem_wait(&lock->rclock);
	lock->rcount -= 1;
	ncount = lock->rcount;
	sem_post(&lock->rclock);
	if (ncount == 0) {
		sem_post(&lock->access);
	}
}

