/* SPDX-License-Identifier: MIT */
/*
 * libtraceeval hashtable interface implementation.
 *
 * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */

#include <traceeval-hist.h>

#include "eval-local.h"

__hidden struct hash_table *hash_alloc(void)
{
	struct hash_table *hash;

	hash = calloc(1, sizeof(*hash));
	if (!hash)
		return NULL;

	hash->bits = HASH_BITS;
	hash->hash = calloc(HASH_SIZE(hash->bits), sizeof(*hash->hash));
	if (!hash->hash) {
		free(hash);
		hash = NULL;
	}

	return hash;
}

__hidden void hash_free(struct hash_table *hash)
{
	free(hash->hash);
	free(hash);
}

__hidden void hash_add(struct hash_table *hash, struct hash_item *item, unsigned key)
{
	key &= HASH_MASK(hash->bits);

	item->next = hash->hash[key];
	hash->hash[key] = item;
	item->key = key;

	hash->nr_items++;
}

__hidden int hash_remove(struct hash_table *hash, struct hash_item *item)
{
	struct hash_item **parent;

	for (parent = &hash->hash[item->key]; *parent; parent = &(*parent)->next) {
		if (*parent == item) {
			*parent = item->next;
			hash->nr_items--;
			return 1;
		}
	}
	return 0;
}

__hidden struct hash_iter *hash_iter_start(struct hash_table *hash)
{
	struct hash_iter *iter = &hash->iter;
	size_t i;

	for (i = 0; i < HASH_SIZE(hash->bits); i++) {
		if (!hash->hash[i])
			continue;
		iter->next_item = hash->hash[i];
		break;
	}
	iter->current_bucket = i;
	return iter;
}

__hidden struct hash_item *hash_iter_next(struct hash_iter *iter)
{
	struct hash_table *hash = container_of(iter, struct hash_table, iter);
	struct hash_item *item;

	if (iter->current_bucket >= HASH_SIZE(hash->bits))
		return NULL;

	item = iter->next_item;
	if (!item)
		return NULL;

	iter->next_item = item->next;
	if (!iter->next_item) {
		size_t i;

		for (i = iter->current_bucket + 1; i < HASH_SIZE(hash->bits); i++) {
			if (!hash->hash[i])
				continue;
			iter->next_item = hash->hash[i];
			break;
		}
		iter->current_bucket = i;
	}
	return item;
}

__hidden struct hash_iter *hash_iter_bucket(struct hash_table *hash, unsigned key)
{
	struct hash_iter *iter = &hash->iter;

	key &= HASH_MASK(hash->bits);

	iter->current_bucket = key;
	iter->next_item = hash->hash[key];

	return iter;
}

__hidden struct hash_item *hash_iter_bucket_next(struct hash_iter *iter)
{
	struct hash_item *item = iter->next_item;

	if (item)
		iter->next_item = item->next;

	return item;
}
