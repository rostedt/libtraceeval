/* SPDX-License-Identifier: MIT */
/*
 * libtraceeval histogram interface implementation.
 *
 * Copyright (C) 2023 Google Inc, Stevie Alvarez <stevie.6strings@gmail.com>
 * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */

#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include <traceeval-hist.h>
#include "eval-local.h"

/*
 * print_err - print an error message
 * @fmt: String format
 * @...: (optional) Additional arguments to print in conjunction with @format
 */
static void print_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

/*
 * Compare traceeval_data instances.
 *
 * Return 0 if @orig and @copy are the same, 1 if @orig is greater than @copy,
 * -1 for the other way around, and -2 on error.
 */
static int compare_traceeval_data(struct traceeval *teval,
				  struct traceeval_type *type,
				  const struct traceeval_data *orig,
				  const struct traceeval_data *copy)
{
	int i;

	if (orig == copy)
		return 0;

	if (!orig)
		return -1;

	if (!copy)
		return 1;

	if (type->cmp)
		return type->cmp(teval, type, orig, copy);

	switch (type->type) {
	case TRACEEVAL_TYPE_STRING:
		i = strcmp(orig->string, copy->string);
		compare_numbers_return(i, 0);

	case TRACEEVAL_TYPE_NUMBER:
		compare_numbers_return(orig->number, copy->number);

	case TRACEEVAL_TYPE_NUMBER_64:
		compare_numbers_return(orig->number_64, copy->number_64);

	case TRACEEVAL_TYPE_NUMBER_32:
		compare_numbers_return(orig->number_32, copy->number_32);

	case TRACEEVAL_TYPE_NUMBER_16:
		compare_numbers_return(orig->number_16, copy->number_16);

	case TRACEEVAL_TYPE_NUMBER_8:
		compare_numbers_return(orig->number_8, copy->number_8);

	default:
		print_err("%d is an invalid enum traceeval_data_type member",
				type->type);
		return -2;
	}
}

/*
 * Compare arrays of struct traceeval_data's with respect to @def.
 *
 * Return 1 if @orig and @copy are the same, 0 if not, and -1 on error.
 */
static int compare_traceeval_data_set(struct traceeval *teval,
				      struct traceeval_type *defs,
				      struct traceeval_data *orig,
				      const struct traceeval_data *copy, size_t size)
{
	int check;
	size_t i;

	/* compare data arrays */
	for (i = 0; i < size; i++) {
		if ((check = compare_traceeval_data(teval, defs + i, orig + i, copy + i)))
			return check == -2 ? -1 : 0;
	}

	return 1;
}

/*
 * type_release - free a struct traceeval_type array
 * @defs: The array to release
 * @len: The length of @defs
 *
 * It is assumed that all elements of @defs, within the length of @len, have
 * name fields initialized to valid pointers.
 *
 * This function was designed to be used on an array allocated by type_alloc().
 * Note that type_alloc() initializes all name fields of elements within the
 * returned size.
 */
static void type_release(struct traceeval_type *defs, size_t len)
{
	if (!defs)
		return;

	for (size_t i = 0; i < len; i++) {
		free(defs[i].name);
	}

	free(defs);
}

/*
 * type_alloc - clone a struct traceeval_type array
 * @defs: The original array
 * @copy: A pointer to where to place the @defs copy
 *
 * Clone traceeval_type array @defs to the heap, and place in @copy.
 * @defs must be terminated with an instance of type TRACEEVAL_TYPE_NONE.
 *
 * The size of the copy pointed to by @copy is returned. It counts all elements
 * in @defs excluding the terminating TRACEEVAL_TYPE_NONE traceeval_type.
 * The copy contains everything from @defs excluding the TRACEEVAL_TYPE_NONE
 * traceeval_type.
 * On error, copy is set to point to NULL.
 *
 * The name field of each element of @defs (except for the terminating
 * TRACEEVAL_TYPE_NONE) must be a NULL-terminated string. The validity of the
 * name field is not checked, but errors are returned upon finding unset name
 * fields and string duplication failures. It is guaranteed that all elements
 * of the copy within the returned size have valid pointers in their name
 * fields.
 *
 * Returns the size of the array pointed to by @copy, or -1 on error.
 */
static size_t type_alloc(const struct traceeval_type *defs,
			 struct traceeval_type **copy)
{
	struct traceeval_type *new_defs = NULL;
	size_t size;
	ssize_t i;

	*copy = NULL;

	if (!defs)
		return 0;

	for (size = 0; defs && defs[size].type != TRACEEVAL_TYPE_NONE; size++)
		;

	if (!size)
		return 0;

	new_defs = calloc(size, sizeof(*new_defs));

	for (i = 0; i < size; i++) {
		/* copy current def data to new_def */
		new_defs[i] = defs[i];

		/* copy name to heap, ensures name copied */
		if (!defs[i].name)
			goto fail;
		new_defs[i].name = strdup(defs[i].name);

		if (!new_defs[i].name)
			goto fail;
	}

	*copy = new_defs;
	return size;

fail:
	if (defs[i].name)
		print_err("Failed to allocate traceeval_type %zu", size);
	else
		print_err("traceeval_type list missing a name");

	for (; i >= 0; i--)
		free(new_defs[i].name);
	free(new_defs);
	return -1;
}

static int check_keys(struct traceeval_type *keys)
{
	for (int i = 0; keys[i].type != TRACEEVAL_TYPE_NONE; i++) {
		/* Define this as a key */
		keys[i].flags |= TRACEEVAL_FL_KEY;
		keys[i].flags &= ~TRACEEVAL_FL_VALUE;

		keys[i].index = i;

		switch (keys[i].type) {
		case TRACEEVAL_TYPE_POINTER:
			/* Key pointer types must have a cmp and hash function */
			if (!keys[i].cmp || !keys[i].hash)
				return -1;
			break;
		default:
			break;
		}
	}
	return 0;
}

static int check_vals(struct traceeval_type *vals)
{
	for (int i = 0; vals[i].type != TRACEEVAL_TYPE_NONE; i++) {
		/* Define this as a value */
		vals[i].flags |= TRACEEVAL_FL_VALUE;
		vals[i].flags &= ~TRACEEVAL_FL_KEY;

		vals[i].index = i;
	}
	return 0;
}

/*
 * traceeval_init_data_size - create a traceeval descriptor
 * @keys: Defines the keys to differentiate traceeval entries
 * @vals: Defines values attached to entries differentiated by @keys.
 * @sizeof_type: The size of struct traceeval_type
 * @sizeof_data: The size of struct traceeval_data
 *
 * The @keys and @vals define how the traceeval instance will be populated.
 * The @keys will be used by traceeval_query() to find an instance within
 * the "histogram". Note, both the @keys and @vals array must end with:
 * { .type = TRACEEVAL_TYPE_NONE }.
 *
 * The @keys and @vals passed in are copied for internal use, but they are
 * still modified to add the flags to denote their type (key or value) as
 * well as the index into the keys or vals array respectively. This is
 * to help speed up other operations that may need to know the index of
 * the given type, and remove the burden from the user to make sure they
 * are added.
 *
 * For any member of @keys or @vals that isn't of type TRACEEVAL_TYPE_NONE,
 * the name field must be a null-terminated string. Members of type
 * TRACEEVAL_TYPE_NONE are used to terminate the array, therefore their other
 * fields are ignored.
 *
 * @vals can be NULL or start with its type field as TRACEEVAL_TYPE_NONE to
 * define the values of the histogram to be empty.
 * @keys must be populated with at least one element that is not of type
 * TRACEEVAL_TYPE_NONE.
 *
 * The @sizeof_type and @sizeof_data are used to handle backward compatibility
 * in the event that items are added to them. All the existing functions
 * will still need to work with the older sizes.
 *
 * Returns the descriptor on success, or NULL on error.
 */
struct traceeval *traceeval_init_data_size(struct traceeval_type *keys,
					   struct traceeval_type *vals,
					   size_t sizeof_type, size_t sizeof_data)
{
	struct traceeval *teval;
	char *err_msg;
	int ret;

	if (!keys)
		return NULL;

	if (keys->type == TRACEEVAL_TYPE_NONE) {
		err_msg = "Keys cannot start with type TRACEEVAL_TYPE_NONE";
		goto fail;
	}

	/* alloc teval */
	teval = calloc(1, sizeof(*teval));
	if (!teval) {
		err_msg = "Failed to allocate memory for traceeval instance";
		goto fail;
	}

	ret = check_keys(keys);
	if (ret < 0)
		goto fail_release;

	if (vals) {
		ret = check_vals(vals);
		if (ret < 0)
			goto fail_release;
	}

	/* alloc key types */
	teval->nr_key_types = type_alloc(keys, &teval->key_types);
	if (teval->nr_key_types <= 0) {
		err_msg = "Failed to allocate user defined keys";
		goto fail_release;
	}

	/* alloc val types */
	teval->nr_val_types = type_alloc(vals, &teval->val_types);
	if (teval->nr_val_types < 0) {
		err_msg = "Failed to allocate user defined values";
		goto fail_release;
	}

	/* alloc hist */
	teval->hist = hash_alloc();
	if (!teval->hist) {
		err_msg = "Failed to allocate memory for histogram";
		goto fail_release;
	}

	teval->sizeof_type = sizeof_type;
	teval->sizeof_data = sizeof_data;

	return teval;

fail_release:
	traceeval_release(teval);

fail:
	print_err(err_msg);
	return NULL;
}

/*
 * Free up allocated data.
 */
static void clean_data(struct traceeval_data *data, struct traceeval_type *type)
{
		if (type->release)
			type->release(type, data);

		switch (type->type) {
		case TRACEEVAL_TYPE_STRING:
			free(data->string);
			break;
		default:
			break;
		}
}

/*
 * Free up allocated memory from @data.
 */
static void clean_data_set(struct traceeval_data *data, struct traceeval_type *defs,
		       size_t size)
{
	size_t i;

	if (!data || !defs) {
		if (data)
			print_err("Data to be freed without accompanied types!");
		return;
	}

	for (i = 0; i < size; i++)
		clean_data(data + i, defs + i);

	free(data);
}

/*
 * Free all possible data stored within the entry.
 */
static void free_entry(struct traceeval *teval, struct entry *entry)
{
	if (!entry)
		return;

	clean_data_set(entry->keys, teval->key_types, teval->nr_key_types);
	clean_data_set(entry->vals, teval->val_types, teval->nr_val_types);

	free(entry);
}

/*
 * Free the hist_table allocated to a traceeval instance.
 */
static void hist_table_release(struct traceeval *teval)
{
	struct hash_table *hist = teval->hist;
	struct hash_iter *iter;
	struct hash_item *item;

	if (!hist)
		return;

	for (iter = hash_iter_start(hist); (item = hash_iter_next(iter)); ) {
		struct entry *entry = container_of(item, struct entry, hash);

		hash_remove(hist, &entry->hash);
		free_entry(teval, entry);
	}

	hash_free(hist);
	teval->hist = NULL;
}

/*
 * traceeval_release - release a traceeval descriptor
 * @teval: An instance of traceeval returned by traceeval_init()
 *
 * When the caller of traceeval_init() is done with the returned @teval,
 * it must call traceeval_release().
 *
 * This frees all internally allocated data of @teval and will call the
 * corresponding release() functions registered for keys and values.
 */
void traceeval_release(struct traceeval *teval)
{
	if (!teval)
		return;

	hist_table_release(teval);
	type_release(teval->key_types, teval->nr_key_types);
	type_release(teval->val_types, teval->nr_val_types);
	teval->key_types = NULL;
	teval->val_types = NULL;
	free(teval);
}

static unsigned make_hash(struct traceeval *teval, const struct traceeval_data *keys,
			  int bits)
{
	const struct traceeval_type *types = teval->key_types;
	unsigned long long val;
	unsigned key = 0;
	int nr = teval->nr_key_types;

	for (int i = 0; i < nr; i++) {
		if (types[i].hash) {
			key += types[i].hash(teval, &types[i], &keys[i]);
			continue;
		}

		switch (types[i].type) {
		case TRACEEVAL_TYPE_NUMBER_8:
		case TRACEEVAL_TYPE_NUMBER_16:
		case TRACEEVAL_TYPE_NUMBER_32:
		case TRACEEVAL_TYPE_NUMBER_64:
		case TRACEEVAL_TYPE_NUMBER:
			val = keys[i].number_64;
			break;
		case TRACEEVAL_TYPE_STRING:
			val = hash_string(keys[i].cstring);
			break;
		default:
			val = 0;
		}
		key += hash_number(val);
	}

	return key;
}

/*
 * Find the entry that @keys corresponds to within @teval.
 *
 * Returns 1 on success, 0 if no match found, -1 on error.
 */
static int get_entry(struct traceeval *teval, const struct traceeval_data *keys,
		     struct entry **result)
{
	struct hash_table *hist = teval->hist;
	struct entry *entry = NULL;
	struct hash_iter *iter;
	struct hash_item *item;
	unsigned key;
	int check = 0;
	int i;

	if (!teval || !keys)
		return -1;

	for (i = 0; i < teval->nr_key_types; i++) {
		if (keys[i].type != teval->key_types[i].type)
			return -1;
	}

	key = make_hash(teval, keys, hist->bits);

	for (iter = hash_iter_bucket(hist, key); (item = hash_iter_bucket_next(iter)); ) {
		entry = container_of(item, struct entry, hash);

		check = compare_traceeval_data_set(teval, teval->key_types,
						   entry->keys, keys, teval->nr_key_types);
		if (check)
			break;
	}

	if (check > 0)
		*result = entry;
	return check;
}

static bool is_stat_type(struct traceeval_type *type)
{
	/* Only value numbers have stats */
	if (!(type->flags & TRACEEVAL_FL_VALUE) ||
	    !(type->flags & TRACEEVAL_FL_STAT))
		return false;

	switch (type->type) {
	case TRACEEVAL_TYPE_NUMBER:
	case TRACEEVAL_TYPE_NUMBER_64:
	case TRACEEVAL_TYPE_NUMBER_32:
	case TRACEEVAL_TYPE_NUMBER_16:
	case TRACEEVAL_TYPE_NUMBER_8:
		return true;
	default:
		return false;
	}
}

/*
 * Copy @src to @dst with respect to @type.
 *
 * Return 0 on success, -1 on error.
 */
static int copy_traceeval_data(struct traceeval_type *type,
			       struct traceeval_stat *stat,
			       struct traceeval_data *dst,
			       const struct traceeval_data *src)
{
	unsigned long long val;

	if (type->copy)
		return type->copy(type, dst, src);

	*dst = *src;

	switch(type->type) {
	case TRACEEVAL_TYPE_NUMBER:
		if (type->flags & TRACEEVAL_FL_SIGNED)
			val = (long long)dst->number;
		else
			val = (unsigned long long)dst->number;
		break;

	case TRACEEVAL_TYPE_NUMBER_64:
		if (type->flags & TRACEEVAL_FL_SIGNED)
			val = (long long)dst->number_64;
		else
			val = (unsigned long long)dst->number_64;
		break;

	case TRACEEVAL_TYPE_NUMBER_32:
		if (type->flags & TRACEEVAL_FL_SIGNED)
			val = (long long)dst->number_32;
		else
			val = (unsigned long long)dst->number_32;
		break;

	case TRACEEVAL_TYPE_NUMBER_16:
		if (type->flags & TRACEEVAL_FL_SIGNED)
			val = (long long)dst->number_16;
		else
			val = (unsigned long long)dst->number_16;
		break;

	case TRACEEVAL_TYPE_NUMBER_8:
		if (type->flags & TRACEEVAL_FL_SIGNED)
			val = (long long)dst->number_8;
		else
			val = (unsigned long long)dst->number_8;
		break;

	case TRACEEVAL_TYPE_STRING:
		dst->string = NULL;

		if (src->string)
			dst->string = strdup(src->string);

		if (!dst->string)
			return -1;
		return 0;
	default:
		return 0;
	}

	if (!stat || !is_stat_type(type))
		return 0;

	if (!stat->count++) {
		stat->max = val;
		stat->min = val;
		stat->total = val;
		return 0;
	}

	if (type->flags & TRACEEVAL_FL_SIGNED) {
		if ((long long)stat->max < (long long)val)
			stat->max = val;
		if ((long long)stat->min > (long long)val)
			stat->min = val;
		stat->total += (long long)val;
	} else {
		if (stat->max < val)
			stat->max = val;
		if (stat->min > val)
			stat->min = val;
		stat->total += val;
	}

	return 0;
}

/*
 * Free @data with respect to @size and @type.
 *
 * Does not call the release() callback if a copy() exists.
 */
static void data_release(size_t size, struct traceeval_data *data,
			 struct traceeval_type *type)
{
	for (size_t i = 0; i < size; i++) {
		/* A copy should handle releases */
		if (type[i].release && !type[i].copy)
			type[i].release(&type[i], &data[i]);

		if (type[i].type == TRACEEVAL_TYPE_STRING)
			free(data[i].string);
	}
}

static void data_release_and_free(size_t size, struct traceeval_data **data,
				struct traceeval_type *type)
{
	data_release(size, *data, type);
	free(*data);
	*data = NULL;
}

/*
 * Duplicate a traceeval_data @orig into an newly allocated @copy.
 *
 * Returns 1 on success, -1 on error.
 */
static int dup_traceeval_data_set(size_t size, struct traceeval_type *type,
				  struct traceeval_stat *stats,
				  const struct traceeval_data *orig,
				  struct traceeval_data **copy)
{
	size_t i;

	*copy = NULL;
	if (!size)
		return 1;

	*copy = calloc(size, sizeof(**copy));
	if (!*copy)
		return -1;

	for (i = 0; i < size; i++) {
		if (copy_traceeval_data(type + i, stats ? stats + i : NULL,
					 (*copy) + i, orig + i))
			goto fail;
	}

	return 1;

fail:
	data_release_and_free(i, copy, type);
	return -1;
}


/*
 * traceeval_query - find the last instance defined by the keys
 * @teval: The descriptor to search from
 * @keys: A list of data to look for
 * @results: A pointer to where to place the results (if found)
 *
 * This does a lookup for an instance within the traceeval data.
 * The @keys is an array defined by the keys declared in traceeval_init().
 * The @keys will return an item that had the same keys when it was
 * inserted by traceeval_insert(). The @keys here follow the same rules
 * as the keys for traceeval_insert().
 *
 * Note, when the caller is done with @results, it must call
 * traceeval_results_release() on it.
 *
 * Returns 1 if found, 0 if not found, and -1 on error.
 */
int traceeval_query_size(struct traceeval *teval, const struct traceeval_data *keys,
			 size_t nr_keys, const struct traceeval_data **results)
{
	struct entry *entry;
	int check;

	if (!teval || !keys || !results)
		return -1;

	if (nr_keys != teval->nr_key_types)
		return -1;

	/* find key and copy its corresponding value pair */
	if ((check = get_entry(teval, keys, &entry)) < 1)
		return check;

	*results = entry->vals;
	return 1;
}

/*
 * traceeval_results_release - release the results return by traceeval_query()
 * @teval: The descriptor used in traceeval_query()
 * @results: The results returned by traceeval_query()
 *
 * The @results returned by traceeval_query() is owned by @teval, and
 * how it manages it is implementation specific. The caller should not
 * worry about it. When the caller of traceeval_query() is done with
 * the @results, it must call traceeval_results_release() on it to
 * allow traceeval to clean up its references.
 */
void traceeval_results_release(struct traceeval *teval,
			       const struct traceeval_data *results)
{
	if (!teval || !results) {
		if (!teval)
			print_err("Results to be freed without accompanied traceeval instance!");
		return;
	}
}

static struct entry *create_hist_entry(struct traceeval *teval,
				       const struct traceeval_data *keys)
{
	struct hash_table *hist = teval->hist;
	unsigned key = make_hash(teval, keys, hist->bits);
	struct entry *entry;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return NULL;

	hash_add(hist, &entry->hash, key);

	return entry;
}

/*
 * Create a new entry in @teval with respect to @keys and @vals.
 *
 * Returns 0 on success, -1 on error.
 */
static int create_entry(struct traceeval *teval,
			const struct traceeval_data *keys,
			const struct traceeval_data *vals)
{
	struct traceeval_data *new_keys;
	struct traceeval_data *new_vals;
	struct entry *entry;

	entry = create_hist_entry(teval, keys);
	if (!entry)
		return -1;

	entry->val_stats = calloc(teval->nr_val_types, sizeof(*entry->val_stats));
	if (!entry->val_stats)
		goto fail_entry;

	/* copy keys */
	if (dup_traceeval_data_set(teval->nr_key_types, teval->key_types,
				   NULL, keys, &new_keys) == -1)
		goto fail_stats;

	/* copy vals */
	if (dup_traceeval_data_set(teval->nr_val_types, teval->val_types,
				   entry->val_stats, vals, &new_vals) == -1)
		goto fail;

	entry->keys = new_keys;
	entry->vals = new_vals;

	teval->update_counter++;
	teval->nr_elements++;

	return 0;

fail:
	data_release_and_free(teval->nr_key_types, &new_keys, teval->key_types);

fail_stats:
	free(entry->val_stats);

fail_entry:
	free(entry);
	return -1;
}

/*
 * Update @entry's vals field with a copy of @vals, with respect to @teval.
 *
 * Frees the old vals field of @entry, unless an error occurs.
 *
 * Return 0 on success, -1 on error.
 */
static int update_entry(struct traceeval *teval, struct entry *entry,
			const struct traceeval_data *vals)
{
	struct traceeval_stat *stats = entry->val_stats;
	struct traceeval_type *types = teval->val_types;
	struct traceeval_data *copy = entry->vals;
	struct traceeval_data old[teval->nr_val_types];
	size_t size = teval->nr_val_types;
	ssize_t i;

	if (!size)
		return 0;

	for (i = 0; i < teval->nr_val_types; i++) {
		if (vals[i].type != teval->val_types[i].type)
			return -1;
	}

	for (i = 0; i < size; i++) {
		old[i] = copy[i];

		if (copy_traceeval_data(types + i, stats + i,
					copy + i, vals + i))
			goto fail;
	}
	data_release(size, old, types);
	return 0;
 fail:
	/* Free the new values that were added */
	data_release(i, copy, types);
	/* Put back the old values */
	for (i--; i >= 0; i--) {
		copy_traceeval_data(types + i, NULL,
				    copy + i, old + i);
	}
	return -1;
}

struct traceeval_stat *traceeval_stat_size(struct traceeval *teval,
					   const struct traceeval_data *keys,
					   size_t nr_keys,
					   struct traceeval_type *type)
{
	struct entry *entry;
	int ret;

	if (teval->nr_key_types != nr_keys)
		return NULL;

	if (!is_stat_type(type))
		return NULL;

	ret = get_entry(teval, keys, &entry);
	if (ret <= 0)
		return NULL;

	return &entry->val_stats[type->index];
}

/**
 * traceeval_stat_max - return max value of stat
 * @stat: The stat structure that holds the stats
 *
 * Returns the max value within @stat.
 */
unsigned long long traceeval_stat_max(struct traceeval_stat *stat)
{
	return stat->max;
}

/**
 * traceeval_stat_min - return min value of stat
 * @stat: The stat structure that holds the stats
 *
 * Returns the min value within @stat.
 */
unsigned long long traceeval_stat_min(struct traceeval_stat *stat)
{
	return stat->min;
}

/**
 * traceeval_stat_total - return total value of stat
 * @stat: The stat structure that holds the stats
 *
 * Returns the total value within @stat.
 */
unsigned long long traceeval_stat_total(struct traceeval_stat *stat)
{
	return stat->total;
}

/**
 * traceeval_stat_count - return count value of stat
 * @stat: The stat structure that holds the stats
 *
 * Returns the count value within @stat.
 */
unsigned long long traceeval_stat_count(struct traceeval_stat *stat)
{
	return stat->count;
}

/*
 * traceeval_insert - insert an item into the traceeval descriptor
 * @teval: The descriptor to insert into
 * @keys: The list of keys that defines what is being inserted.
 * @vals: The list of values that defines what is being inserted.
 *
 * The @keys is an array that holds the data in the order of the keys
 * passed into traceeval_init(). That is, if traceeval_init() had
 * keys = { { .type = TRACEEVAL_STRING }, { .type = TRACEEVAL_NUMBER_8 },
 * { .type = TRACEEVAL_NONE } }; then the @keys array passed in must
 * be a string (char *) followed by a 8 byte number (char).
 *
 * The @keys and @vals are only examined to where it expects data. That is,
 * if the traceeval_init() keys had 3 items where the first two was defining
 * data, and the last one was the TRACEEVAL_TYPE_NONE, then the @keys
 * here only needs to be an array of 2, inserting the two items defined
 * by traceeval_init(). The same goes for @vals.
 *
 * If an entry with keys that match @keys exists, it's vals field is freed and
 * set to a copy of @vals. This process calls release() on any data with a
 * type that specified it.
 * Otherwise, a new entry is created with copies of @keys and @vals.
 *
 * For all elements of @keys and @vals that correspond to a struct
 * traceeval_type of type TRACEEVAL_TYPE_STRING, the string field must be set
 * a valid pointer or NULL.
 *
 * On error, @teval is left unchanged.
 *
 * Returns 0 on success, and -1 on error.
 */
int traceeval_insert_size(struct traceeval *teval,
			  const struct traceeval_data *keys, size_t nr_keys,
			  const struct traceeval_data *vals, size_t nr_vals)
{
	struct entry *entry;
	int check;
	int i;

	if (nr_keys != teval->nr_key_types || nr_vals != teval->nr_val_types)
		return -1;

	entry = NULL;
	check = get_entry(teval, keys, &entry);

	for (i = 0; i < teval->nr_val_types; i++) {
		if (vals[i].type != teval->val_types[i].type)
			return -1;
	}

	if (check == -1)
		return check;

	/* insert key-value pair */
	if (check == 0)
		return create_entry(teval, keys, vals);
	else
		return update_entry(teval, entry, vals);
}

/**
 * traceeval_remove - remove an item from the traceeval descriptor
 * @teval: The descriptor to removed from
 * @keys: The list of keys that defines what is being removed
 * @nr_keys: Size of @keys.
 *
 * This is the opposite of traceeval_insert(). Instead of inserting
 * an item into the traceeval historgram, it removes it.
 *
 * Returns 1 if it found and removed an item,
 *         0 if it did not find an time matching @keys
 *        -1 if there was an error.
 */
int traceeval_remove_size(struct traceeval *teval,
			  const struct traceeval_data *keys, size_t nr_keys)
{
	struct hash_table *hist = teval->hist;
	struct entry *entry;
	int check;

	if (teval->nr_key_types != nr_keys)
		return -1;

	entry = NULL;
	check = get_entry(teval, keys, &entry);

	if (check < 1)
		return check;

	hash_remove(hist, &entry->hash);
	free_entry(teval, entry);

	/* update_counter is used to know if there was an update. */
	teval->update_counter++;

	/* nr_elements keeps track of the number of stored elemnets */
	teval->nr_elements--;

	return 1;
}

/**
 * traceeval_count - Return the number of elements in the traceeval
 * @teval: The traceeval handle to get the count from
 *
 * Returns the number of elements stored by unique keys in the @teval.
 */
size_t traceeval_count(struct traceeval *teval)
{
	return teval->nr_elements;
}

/**
 * traceeval_iterator_put - release a given iterator
 * @iter: The iterartor to release
 *
 * Frees the resources of an @iter that was created by
 * traceeval_iterator_get().
 */
void traceeval_iterator_put(struct traceeval_iterator *iter)
{
	if (!iter)
		return;

	free(iter->direction);
	free(iter->entries);
	free(iter->sort);
	free(iter);
}

static int create_iter_array(struct traceeval_iterator *iter)
{
	struct traceeval *teval = iter->teval;
	struct hash_table *hist = teval->hist;
	struct hash_iter *hiter;
	struct hash_item *item;
	int i;

	iter->nr_entries = hash_nr_items(hist);
	iter->entries = calloc(iter->nr_entries, sizeof(*iter->entries));
	if (!iter->entries)
		return -1;

	for (i = 0, hiter = hash_iter_start(hist); (item = hash_iter_next(hiter)); i++) {
		struct entry *entry = container_of(item, struct entry, hash);

		iter->entries[i] = entry;
	}

	/* Loop must match entries */
	if (i != iter->nr_entries) {
		free(iter->entries);
		iter->entries = NULL;
		return -1;
	}

	iter->update_counter = teval->update_counter;

	return 0;
}

/**
 * traceeval_iterator_get - get a handle to iterate over a given traceeval
 * @teval: The traceeval handle to iterate over
 *
 * Returns a handle to iterate over the given @teval. Must be freed with
 * traceeval_iterator_put(). It can be used with traceeval_iterator_next()
 * to retrieve the keys of the next entry in @teval.
 *
 * Use traceeval_iterator_sort() to specify the order of the entries
 * returned by traceeval_iterator_next().
 *
 * Returns an allocated iterator on success, and NULL on failure.
 */
struct traceeval_iterator *traceeval_iterator_get(struct traceeval *teval)
{
	struct traceeval_iterator *iter;
	int ret;

	iter = calloc(1, sizeof(*iter));
	if (!iter)
		return NULL;

	iter->teval = teval;

	ret = create_iter_array(iter);

	if (ret < 0) {
		free(iter);
		iter = NULL;
	}

	return iter;
}

static struct traceeval_type *find_sort_type(struct traceeval *teval,
					     const char *name)
{
	struct traceeval_type *type;
	int i;

	/* Check values first, and then keys */
	for (i = 0; i < teval->nr_val_types; i++) {
		type = &teval->val_types[i];

		if (strcmp(type->name, name) == 0)
			return type;
	}

	for (i = 0; i < teval->nr_key_types; i++) {
		type = &teval->key_types[i];

		if (strcmp(type->name, name) == 0)
			return type;
	}

	return NULL;
}

/**
 * traceeval_iterator_sort - sort the entries that an iterator will return
 * @iter: The iterator to specify the sort order of the entries
 * @sort_field: The name of the key or value to sort with.
 * @level: The level of sorting (0 for first order, 1 for second, ...)
 * @ascending: If the sort should go forward or backward.
 *
 * The iterator has a list of entries to produce with traceeval_iterator_next().
 * This function specifies what the order of the output of that function will
 * be. Note, whenever this function is called, it resets the @iter so that
 * the traceveal_iterator_next() will start from the beginning again.
 *
 * In other words, be very careful to ever call this function in a middle
 * of a loop that is using traceeval_iterator_next(), otherwise you may end
 * up in an infinite loop!
 *
 * The @level specifies the level of sorting. That is, for @level = 0,
 * it will decide the main sorting of the @iter. For @level = 1, it will
 * be the tie breaker for two entries that are equal for the @level = 0
 * sort. @level = 2, will be the tie breaker for @level = 1, and so on.
 *
 * Note, if traceeval_iterator_next() is called, and there's a missing @level,
 * it will fail. That is, if this function is called once with @level = 0 and
 * againg with @level = 2, but never with @level = 1, the call to
 * traceeval_iterator_next() will fail.
 *
 * If this function is called multiple times with the same @level, then the
 * last call will define the what that @level will do.
 *
 * The @ascending will determine if "smaller" items go first if true, and
 * "larger" items go first if false.
 *
 * Return 0 on success and -1 on failure.
 */
int traceeval_iterator_sort(struct traceeval_iterator *iter, const char *sort_field,
			    int level, bool ascending)
{
	bool *direction = iter->direction;
	struct traceeval_type **sort = iter->sort;
	struct traceeval_type *type;
	int num_levels = level + 1;

	type = find_sort_type(iter->teval, sort_field);
	if (!type)
		return -1;

	/* pointer types must have a cmp function */
	switch (type->type) {
	case TRACEEVAL_TYPE_POINTER:
		if (!type->cmp)
			return -1;
		break;
	default:
		break;
	}

	if (num_levels > iter->nr_sort) {
		sort = realloc(sort, sizeof(*sort) * num_levels);
		if (!sort)
			return -1;

		iter->sort = sort;

		direction = realloc(direction, sizeof(*direction) * num_levels);
		if (!direction)
			return -1;

		iter->direction = direction;

		/* Make sure the newly allocated contain NULL */
		for (int i = iter->nr_sort; i < num_levels; i++)
			sort[i] = NULL;

		iter->nr_sort = level + 1;
	}

	sort[level] = type;
	direction[level] = ascending;
	iter->needs_sort = true;
	return 0;
}

static int iter_cmp(const void *A, const void *B, void *data)
{
	struct traceeval_iterator *iter = data;
	struct traceeval *teval = iter->teval;
	const struct entry *a = *((const struct entry **)A);
	const struct entry *b = *((const struct entry **)B);
	int ret;

	for (int i = 0; i < iter->nr_sort; i++) {
		struct traceeval_type *type;
		struct traceeval_data *dataA;
		struct traceeval_data *dataB;

		type = iter->sort[i];

		if (type->flags & TRACEEVAL_FL_KEY) {
			dataA = &a->keys[type->index];
			dataB = &b->keys[type->index];
		} else {
			dataA = &a->vals[type->index];
			dataB = &b->vals[type->index];
		}

		ret = compare_traceeval_data(teval, type, dataA, dataB);

		if (ret)
			return iter->direction[i] ? ret : ret * -1;
	}

	return 0;
}

static int check_update(struct traceeval_iterator *iter)
{
	struct entry **entries;
	size_t nr_entries;
	int ret;

	/* Was something added or removed from the teval? */
	if (iter->teval->update_counter == iter->update_counter)
		return 0;

	entries = iter->entries;
	nr_entries = iter->nr_entries;

	/* Something changed, need to recreate the array */
	ret = create_iter_array(iter);
	if (ret < 0) {
		iter->entries = entries;
		iter->nr_entries = nr_entries;
		return -1;
	}
	free(entries);

	return 0;
}

static int sort_iter(struct traceeval_iterator *iter)
{
	int i;

	/* Make sure all levels are filled */
	for (i = 0; i < iter->nr_sort; i++) {
		if (!iter->sort[i])
			return -1;
	}

	if (check_update(iter) < 0)
		return -1;

	qsort_r(iter->entries, iter->nr_entries, sizeof(*iter->entries),
		iter_cmp, iter);

	iter->needs_sort = false;
	iter->next = 0;

	return 0;
}

struct iter_custom_data {
	struct traceeval_iterator *iter;
	traceeval_cmp_fn sort_fn;
	void *data;
};

static int iter_custom_cmp(const void *A, const void *B, void *data)
{
	struct iter_custom_data *cust_data = data;
	struct traceeval_iterator *iter = cust_data->iter;
	struct traceeval *teval = iter->teval;
	const struct entry *a = *((const struct entry **)A);
	const struct entry *b = *((const struct entry **)B);

	return cust_data->sort_fn(teval, a->keys, a->vals, b->keys, b->vals,
				  cust_data->data);
}

int traceeval_iterator_sort_custom(struct traceeval_iterator *iter,
				   traceeval_cmp_fn sort_fn, void *data)
{
	struct iter_custom_data cust_data = {
		.iter = iter,
		.sort_fn = sort_fn,
		.data = data
	};

	if (check_update(iter) < 0)
		return -1;

	qsort_r(iter->entries, iter->nr_entries, sizeof(*iter->entries),
		iter_custom_cmp, &cust_data);

	iter->needs_sort = false;
	iter->next = 0;
	return 0;
}

/**
 * traceeval_iterator_next - retrieve the next entry from an iterator
 * @iter: The iterator to retrieve the next entry from
 * @keys: The returned keys of the next entry (if exists)
 *
 * This returns the keys for the next entry in the traceeval being
 * iterated over by @iter. If there are no more entries, 0 is returned
 * and @keys are untouched.
 *
 * Returns 1 if another entry is returned, or 0 if not (or negative on error)
 */
int traceeval_iterator_next(struct traceeval_iterator *iter,
			    const struct traceeval_data **keys)
{
	struct entry *entry;
	int ret;

	if (iter->needs_sort) {
		ret = sort_iter(iter);
		if (ret < 0)
			return ret;
		iter->next = 0;
	}

	do {
		if (iter->next >= iter->nr_entries)
			return 0;

		entry = iter->entries[iter->next++];
	} while (!entry);

	*keys = entry->keys;
	return 1;
}

/**
 * traceeval_iterator_query - return the results from the current entry in the iterator
 * @iter: The iterator to retrieve the entry results from
 * @results: The returned results of the last entry (if exists)
 *
 * This returns the @results of the values from the last instance of
 * traceeval_iterator_next(). It is equivalent of calling:
 *
 * traceeval_query() with the keys returned by traceeval_iterator_next().
 *
 * Except that it will always quickly return the current entry, whereas the
 * traceeval_query() will reset the cached next_entry and do a full
 * lookup again.
 *
 * Returns 1 if another entry is returned, or 0 if not (or negative on error)
 */
int traceeval_iterator_query(struct traceeval_iterator *iter,
			     const struct traceeval_data **results)
{
	struct entry *entry;

	if (iter->next < 1 || iter->next > iter->nr_entries)
		return 0;

	entry = iter->entries[iter->next - 1];
	if (!entry)
		return 0;

	*results = entry->vals;

	return 1;
}

/*
 * traceeval_iterator_results_release - release the results return by traceeval_iterator_query()
 * @iter: The iterator descriptor used in traceeval_iterator_query()
 * @results: The results returned by traceeval_iterator_query()
 *
 * The @results returned by traceeval_iterator_query() is owned by @teval,
 * that is attached to the iterator and how it manages it is implementation
 * specific. The caller should not worry about it. When the caller of
 * traceeval_iterator_query() is done with the @results, it must call
 * traceeval_iterator_results_release() (or traceeval_results_release() if it
 * has the handle of the teval used to get the iterator) on it to allow traceeval
 * to clean up its references.
 */
void traceeval_iterator_results_release(struct traceeval_iterator *iter,
					const struct traceeval_data *results)
{
	if (!iter || !results) {
		if (!iter)
			print_err("Results to be freed without accompanied iterator!");
		return;
	}
}

/**
 * traceeval_iterator_stat - return the stats from the last iterator entry
 * @iter: The iterator to retrieve the stats from
 * @type: The value type to get the stat from
 *
 * Returns the stats of the @type for the current iterator entry on success,
 * or NULL if not found or an error occurred.
 */
struct traceeval_stat *traceeval_iterator_stat(struct traceeval_iterator *iter,
					       struct traceeval_type *type)
{
	struct entry *entry;

	if (!is_stat_type(type))
		return NULL;

	if (iter->next < 1 || iter->next > iter->nr_entries)
		return NULL;

	entry = iter->entries[iter->next - 1];
	return entry ? &entry->val_stats[type->index] : NULL;
}

/**
 * traceeval_iterator_remove - remove the current iterator entry
 * @iter: The iterator to remove the entry from
 *
 * This will remove the current entry from the histogram.
 * This is useful if the current entry should be removed. It will not
 * affect the traceeval_iterator_next().
 *
 * Returns 1 if it successfully removed the entry, 0 if for some reason
 * there was no "current entry" (called before traceeval_iterator_next()).
 */
int traceeval_iterator_remove(struct traceeval_iterator *iter)
{
	struct traceeval *teval = iter->teval;
	struct hash_table *hist = teval->hist;
	struct entry *entry;

	if (iter->next < 1 || iter->next > iter->nr_entries)
		return 0;

	entry = iter->entries[iter->next - 1];
	if (!entry)
		return 0;

	hash_remove(hist, &entry->hash);
	free_entry(teval, entry);

	/* The entry no longer exists */
	iter->entries[iter->next - 1] = NULL;
	teval->update_counter++;
	teval->nr_elements--;

	return 1;
}
