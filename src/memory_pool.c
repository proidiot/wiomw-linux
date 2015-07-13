#include "memory_pool.h"
#include <config.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/* TODO make thread safe */

struct memory_pool {
	/* this is the stack from which we allocate */
	void* next_free;
	/* this is the trigger item in the allocation stack */
	void* threshold_trigger;
	/* this is the next addon pool */
	struct subsequent_memory_pool* next_pool;
	/* this is the optional trigger callback... */
	void (* threshold_cb)(void* threshold_cls);
	/* ...and it's closure */
	void* threshold_cls;
	/* this is the optional malloc failure callback... */
	void (* failure_cb)(void* failure_cls);
	/* ...and it's closure */
	void* failure_cls;
	/* this is the item count of the initial pool
	 * (0 if we defer the first malloc) */
	size_t initial_size;
	/* this is the item count of each of the addon pools
	 * (0 for a fixed pool) */
	size_t subsequent_size;
	/* this is the size of each item in the pools */
	size_t step_size;
	/* this is the optional trigger threshold value
	 * - a negative value means the trigger callback should be called
	 *   when there are -threshold slots left
	 * - a positive value means the trigger callback should be called
	 *   once threshold more slots are used */
	ssize_t threshold;
	/* this is the initial pool */
	unsigned char data[];
};

struct subsequent_memory_pool {
	/* this is the next addon pool */
	struct subsequent_memory_pool* next_pool;
	/* this is the addon pool */
	unsigned char data[];
};

static bool in_pool(struct memory_pool* pool, void* datum)
{
	struct subsequent_memory_pool* next_pool;
	if (pool == NULL) {
		return false;
	}

	if ((pool->initial_size != 0)
			&& (datum >= (void*)(pool->data))
			&& (datum <= ((void*)(pool->data)
				+ ((pool->initial_size - 1)
					* pool->step_size)))) {
		/* datum was in the initial pool */
		return true;
	}

	next_pool = pool->next_pool;

	while (next_pool != NULL) {
		if ((datum >= (void*)(next_pool->data))
				&& (datum <= ((void*)(next_pool->data)
						+ ((pool->subsequent_size - 1)
							* pool->step_size)))) {
			/* datum was in a subsequent pool */
			return true;
		}

		next_pool = next_pool->next_pool;
	}

	/* datum wasn't in any pool */
	return false;
}

struct memory_pool* init_memory_pool(
		size_t initial_size,
		size_t subsequent_size,
		size_t step_size)
{
	struct memory_pool* pool;

	if (step_size == 0
			|| ((initial_size == 0) && (subsequent_size == 0))) {
		/* this would imply a zero-sized pool...
		 * i got yer zero-sized pool right here! */
		return NULL;
	}

	pool = (struct memory_pool*)malloc(
			sizeof(struct memory_pool)
			+ (initial_size * step_size));
	if (pool == NULL) {
		/* failure on first malloc for our pool?
		 * either something is seriously broken,
		 * or someone asked us for a memory pool the size
		 * of the pacific */
		return NULL;
	}

	pool->threshold_trigger = NULL;
	pool->next_pool = NULL;
	pool->threshold_cb = NULL;
	pool->threshold_cls = NULL;
	pool->failure_cb = NULL;
	pool->failure_cls = NULL;
	pool->initial_size = initial_size;
	pool->subsequent_size = subsequent_size;
	pool->step_size = step_size;
	pool->threshold = 0;

	if (initial_size != 0) {
		size_t i = 0;

		for (i = 0; i < (initial_size - 1); i++) {
			/* Each free slot in the memory pool holds a pointer to
			 * the next free slot... */
			*(void**)(pool->data + (i * step_size))
				= (void*)(pool->data + ((i + 1) * step_size));
		}
		/* ...except the final free slot points to NULL. */
		*(void**)(pool->data + (i * step_size)) = NULL;

		pool->next_free = pool->data;
	} else {
		/* no initial memory pool,
		 * only subsequent pools will be made...
		 * this is a good idea if it's not clear
		 * if the pool will even be used */
		pool->next_free = NULL;
	}

	return pool;
}

void set_threshold(
		struct memory_pool* pool,
		ssize_t threshold,
		void (* cb)(void* cls),
		void* cls)
{
	if ((pool == NULL) || (threshold == 0) || (cb == NULL)) {
		/* threshold == 0 doesn't make sense,
		 * and cb == NULL means do nothing */
		return;
	}

	if (threshold > 0) {
		/* threshold > 0 means
		 * "once that many more have been added" */

		pool->threshold_trigger = NULL;
	} else {
		/* threshold < 0 means
		 * "every time there are only this many items left" */

		void* tail = pool->next_free;
		size_t i = -threshold;

		while (i > 0 && tail != NULL) {
			/* search for the true tail */
			i--;
			tail = *(void**)tail;
		}

		if (tail == NULL) {
			/* the tail is less than -threshold away from now,
			 * so the trigger has already been passed */
			cb(cls);
		} else {
			/* the tail is at least -threshold away from next_free,
			 * so the trigger is in the future */
			void* trigger = pool->next_free;

			while (tail != NULL) {
				/* this nifty loop allows us to look for
				 * the true tail while keeping the tail and
				 * trigger variables -threshold away from
				 * each other */
				tail = *(void**)tail;
				trigger = *(void**)trigger;
			}

			/* now that the tail is the true tail,
			 * this is the trigger
			 * (since it is still -threshold before tail) */
			pool->threshold_trigger = trigger;
		}
	}

	pool->threshold = threshold;
	pool->threshold_cb = cb;
	pool->threshold_cls = cls;
}

void set_failure_cb(
		struct memory_pool* pool,
		void (* cb)(void* cls),
		void* cls)
{
	if (cb == NULL) {
		return;
	}

	if (pool == NULL) {
		/* ...apparently we've already failed? */
		cb(cls);
	}

	pool->failure_cb = cb;
	pool->failure_cls = cls;
}

void* pool_alloc(struct memory_pool* pool)
{
	void* new_data;

	if (pool == NULL) {
		return NULL;
	}

	if (pool->next_free == NULL) {
		/* this means we are at the end of a pool,
		 * and we need to allocate a subsequent pool
		 * (we'll let pool_expand handle logic for failures
		 * and fixed pools) */
		pool_expand(pool);

		if (pool->next_free == NULL) {
			/* apparently pool_expand failed
			 * (it should have already dealt with it's failure) */
			return NULL;
		}
	} else if (pool->next_free == pool->threshold_trigger) {
		/* we must be -threshold slots away from
		 * the end of the pool */
		(pool->threshold_cb)(pool->threshold_cls);

		/* we only trigger once
		 * (unless a subsequent pool is added later) */
		pool->threshold_trigger = NULL;
	}

	if (pool->threshold > 1) {
		/* not quite ready to trigger */
		pool->threshold--;
	} else if (pool->threshold == 1) {
		/* time to trigger! */
		(pool->threshold_cb)(pool->threshold_cls);

		pool->threshold = 0;
	}

	/* most of the time, we'll quickly get to here */
	new_data = pool->next_free;
	pool->next_free = *(void**)(pool->next_free);
	return new_data;
}

void pool_free(struct memory_pool* pool, void* datum)
{
	if (pool == NULL) {
		return;
	}

	if (in_pool(pool, datum)) {
		/* the datum wasn't screwy,
		 * so add it to the next_free stack */
		*(void**)datum = pool->next_free;
		pool->next_free = datum;
	}
}

void destroy_pool(struct memory_pool** pool)
{
	struct subsequent_memory_pool* next_pool;
	
	if (pool == NULL || *pool == NULL) {
		return;
	}

	next_pool = (*pool)->next_pool;

	while (next_pool != NULL) {
		/* free each subsequent pool */
		struct subsequent_memory_pool* freeme = next_pool;
		next_pool = next_pool->next_pool;
		free(freeme);
	}

	/* free the initial pool */
	free(*pool);

	*pool = NULL;
}

void pool_expand(struct memory_pool* pool)
{
	size_t i = 0;
	struct subsequent_memory_pool** new_pool;
	void** new_next_free;

	if (pool == NULL) {
		return;
	}

	/* necessary since we'll be storing the new pool's
	 * memory address in the last pool's next_pool */
	new_pool = &(pool->next_pool);
	/* necessary since we'll be adding the new pool's next_free stack
	 * to the bottom of the current next_free stack */
	new_next_free = &(pool->next_free);

	while ((*new_pool) != NULL) {
		new_pool = &((*new_pool)->next_pool);
	}

	*new_pool = (struct subsequent_memory_pool*)malloc(
			sizeof(struct subsequent_memory_pool)
			+ (pool->subsequent_size * pool->step_size));
	if (*new_pool == NULL) {
		/* unable to malloc another pool */
		if (pool->failure_cb != NULL) { 
			(pool->failure_cb)(pool->failure_cls);
			return;
		} else {
			/* TODO error message */
			return;
		}
	}

	(*new_pool)->next_pool = NULL;

	for (i = 0; i < (pool->subsequent_size - 1); i++) {
		/* Each free slot in the memory pool holds a pointer to
		 * the next free slot... */
		*(void**)((*new_pool)->data + (i * pool->step_size))
			= (void*)((*new_pool)->data
					+ ((i + 1) * pool->step_size));
	}
	/* ...except the final free slot points to NULL. */
	*(void**)((*new_pool)->data + (i * pool->step_size)) = NULL;

	while ((*new_next_free) != NULL) {
		/* find the bottom of the next_free stack */
		new_next_free = *(void**)new_next_free;
	}

	/* add the next_free stack of new_pool to the bottom */
	*new_next_free = (*new_pool)->data;
}


