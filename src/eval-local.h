/* SPDX-License-Identifier: MIT */
#ifndef __EVAL_LOCAL_H
#define __EVAL_LOCAL_H

#include <string.h>

#define __hidden __attribute__((visibility ("hidden")))

#define offset_of(type, field) ((size_t)(&(((type *)(NULL))->field)))
#define container_of(ptr, type, field) \
	(type *)((void *)(ptr) - (void *)offset_of(type, field))

#define HASH_BITS 10	/* Start with 1K of buckets */
#define HASH_SIZE(bits)	(1 << (bits))
#define HASH_MASK(bits)	(HASH_SIZE(bits) - 1)

/*
 * Compare two integers of variable length.
 *
 * Return 0 if @a and @b are the same, 1 if @a is greater than @b, and -1
 * if @b is greater than @a.
 */
#define compare_numbers_return(a, b)	\
do {					\
	if ((a) < (b))			\
		return -1;		\
	return (a) != (b);		\
} while (0)				\

struct hash_item {
	struct hash_item	*next;
	unsigned		key;
};

struct hash_iter {
	struct hash_item	*next_item;
	size_t			current_bucket;
};

/* A table of key-value entries */
struct hash_table {
	struct hash_item	**hash;
	unsigned		bits;
	size_t			nr_items;
	struct hash_iter	iter;
};

struct traceeval_stat {
	unsigned long long	max;
	unsigned long long	min;
	unsigned long long	total;
	unsigned long long	std;
	size_t			count;
};

/* A key-value pair */
struct entry {
	struct hash_item	hash;
	struct traceeval_data	*keys;
	struct traceeval_data	*vals;
	struct traceeval_stat	*val_stats;
};

/* Histogram */
struct traceeval {
	struct traceeval_type		*key_types;
	struct traceeval_type		*val_types;
	struct hash_table		*hist;
	size_t				nr_key_types;
	size_t				nr_val_types;
	size_t				update_counter;
	size_t				sizeof_type;
	size_t				sizeof_data;
};

struct traceeval_iterator {
	struct traceeval		*teval;
	struct entry			**entries;
	struct traceeval_type		**sort;
	bool				*direction;
	size_t				update_counter;
	size_t				nr_entries;
	size_t				nr_sort;
	size_t				next;
	bool				needs_sort;
};

extern struct hash_table *hash_alloc(void);
extern void hash_free(struct hash_table *hash);
extern void hash_add(struct hash_table *hash, struct hash_item *item, unsigned key);
extern int hash_remove(struct hash_table *hash, struct hash_item *item);

extern struct hash_iter *hash_iter_start(struct hash_table *hash);
extern struct hash_item *hash_iter_next(struct hash_iter *iter);

extern struct hash_iter *hash_iter_bucket(struct hash_table *hash, unsigned key);
extern struct hash_item *hash_iter_bucket_next(struct hash_iter *iter);

static inline size_t hash_nr_items(struct hash_table *hash)
{
	return hash->nr_items;
}

static inline unsigned long long hash_string(const char *str)
{
	unsigned long long key = 0;
	int len = strlen(str);
	int i;

	for (i = 0; i < len; i++)
		key += (unsigned long long)str[i] << ((i & 7) * 8);

	return key;
}

 /*
 * This is a quick hashing function adapted from Donald E. Knuth's 32
 * bit multiplicative hash. See The Art of Computer Programming (TAOCP).
 * Multiplication by the Prime number, closest to the golden ratio of
 * 2^32.
 */
static inline unsigned long long hash_number(unsigned long long val)
{
		return val * 2654435761ULL;
}

#endif
