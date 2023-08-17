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
				  union traceeval_data *orig,
				  const union traceeval_data *copy)
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

	case TRACEEVAL_TYPE_DYNAMIC:
		/* If it didn't specify a cmp function, then punt */
		return 0;

	default:
		print_err("%d is an invalid enum traceeval_data_type member",
				type->type);
		return -2;
	}
}

/*
 * Compare arrays of union traceeval_data's with respect to @def.
 *
 * Return 1 if @orig and @copy are the same, 0 if not, and -1 on error.
 */
static int compare_traceeval_data_set(struct traceeval *teval,
				      struct traceeval_type *defs,
				      union traceeval_data *orig,
				      const union traceeval_data *copy, size_t size)
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
	size_t i;

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

	for (; i >=0; i--)
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
		case TRACEEVAL_TYPE_DYNAMIC:
			/*
			 * Key pointers and dynamic types must have a
			 * cmp and hash function
			 */
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
 * traceeval_init - create a traceeval descriptor
 * @keys: Defines the keys to differentiate traceeval entries
 * @vals: Defines values attached to entries differentiated by @keys.
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
 * Returns the descriptor on success, or NULL on error.
 */
struct traceeval *traceeval_init(struct traceeval_type *keys,
				 struct traceeval_type *vals)
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

	return teval;

fail_release:
	traceeval_release(teval);

fail:
	print_err(err_msg);
	return NULL;
}

/*
 * Frees dynamic data in @data if @type specifies a dynamic data type.
 */
static void clean_data(union traceeval_data *data, struct traceeval_type *type)
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
 * Free any specified dynamic data in @data.
 */
static void clean_data_set(union traceeval_data *data, struct traceeval_type *defs,
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

	/* free dynamic traceeval_data */
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
 * corresponding release() functions registered for keys and values of
 * type TRACEEVAL_TYPE_DYNAMIC.
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

static unsigned make_hash(struct traceeval *teval, const union traceeval_data *keys,
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
static int get_entry(struct traceeval *teval, const union traceeval_data *keys,
		     struct entry **result)
{
	struct hash_table *hist = teval->hist;
	struct entry *entry = NULL;
	struct hash_iter *iter;
	struct hash_item *item;
	unsigned key;
	int check = 0;

	if (!teval || !keys)
		return -1;

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

/*
 * Copy @src to @dst with respect to @type.
 *
 * Return 0 on success, -1 on error.
 */
static int copy_traceeval_data(struct traceeval_type *type,
			       struct traceeval_stat *stat,
			       union traceeval_data *dst,
			       const union traceeval_data *src)
{
	unsigned long long val;

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

	if (!stat)
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
 * Does not call the release callback on the data.
 */
static void data_release(size_t size, union traceeval_data **data,
				struct traceeval_type *type)
{
	for (size_t i = 0; i < size; i++) {
		if (type[i].type == TRACEEVAL_TYPE_STRING)
			free((*data)[i].string);
	}
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
				  const union traceeval_data *orig,
				  union traceeval_data **copy)
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
	data_release(i, copy, type);
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
int traceeval_query(struct traceeval *teval, const union traceeval_data *keys,
		    union traceeval_data **results)
{
	struct entry *entry;
	int check;

	if (!teval || !keys || !results)
		return -1;

	/* find key and copy its corresponding value pair */
	if ((check = get_entry(teval, keys, &entry)) < 1)
		return check;

	return dup_traceeval_data_set(teval->nr_val_types, teval->val_types,
				      NULL, entry->vals, results);
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
			       union traceeval_data *results)
{
	if (!teval || !results) {
		if (!teval)
			print_err("Results to be freed without accompanied traceeval instance!");
		return;
	}

	data_release(teval->nr_val_types, &results, teval->val_types);
}

static struct entry *create_hist_entry(struct traceeval *teval,
				       const union traceeval_data *keys)
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
			const union traceeval_data *keys,
			const union traceeval_data *vals)
{
	union traceeval_data *new_keys;
	union traceeval_data *new_vals;
	struct entry *entry;

	entry = create_hist_entry(teval, keys);
	if (!entry)
		return -1;

	entry->val_stats = calloc(teval->nr_key_types, sizeof(*entry->val_stats));
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

	return 0;

fail:
	data_release(teval->nr_key_types, &new_keys, teval->key_types);

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
			const union traceeval_data *vals)
{
	union traceeval_data *new_vals;

	if (dup_traceeval_data_set(teval->nr_val_types, teval->val_types,
				   entry->val_stats, vals, &new_vals) == -1)
		return -1;

	clean_data_set(entry->vals, teval->val_types, teval->nr_val_types);
	entry->vals = new_vals;
	return 0;
}

struct traceeval_stat *traceeval_stat(struct traceeval *teval,
				      const union traceeval_data *keys,
				      struct traceeval_type *type)
{
	struct entry *entry;
	int ret;

	/* Only value numbers have stats */
	if (!(type->flags & TRACEEVAL_FL_VALUE))
		return NULL;

	switch (type->type) {
	case TRACEEVAL_TYPE_NUMBER:
	case TRACEEVAL_TYPE_NUMBER_64:
	case TRACEEVAL_TYPE_NUMBER_32:
	case TRACEEVAL_TYPE_NUMBER_16:
	case TRACEEVAL_TYPE_NUMBER_8:
		break;
	default:
		return NULL;
	}

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
 * set to a copy of @vals. This process calls dyn_release() on any data of
 * type TRACEEVAL_TYPE_DYNAMIC.
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
int traceeval_insert(struct traceeval *teval,
		     const union traceeval_data *keys,
		     const union traceeval_data *vals)
{
	struct entry *entry;
	int check;

	entry = NULL;
	check = get_entry(teval, keys, &entry);

	if (check == -1)
		return check;

	/* insert key-value pair */
	if (check == 0)
		return create_entry(teval, keys, vals);
	else
		return update_entry(teval, entry, vals);
}
