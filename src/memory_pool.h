#ifndef _WIOMW_MEMORY_POOL_H_
#define _WIOMW_MEMORY_POOL_H_

#include <stddef.h>
#include <unistd.h>

struct memory_pool* init_memory_pool(
		size_t initial_size,
		size_t subsequent_size,
		size_t step_size);

void set_threshold(
		struct memory_pool* pool,
		ssize_t threshold,
		void (* threshold_cb)(void* cls),
		void* cls);

void set_failure_cb(
		struct memory_pool* pool,
		void (* failure_cb)(void* cls),
		void* cls);

void* pool_alloc(struct memory_pool* pool);

void pool_free(struct memory_pool* pool, void* datum);

void destroy_pool(struct memory_pool** pool);

void pool_expand(struct memory_pool* pool);

#endif
