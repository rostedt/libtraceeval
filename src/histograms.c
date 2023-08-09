/* SPDX-License-Identifier: MIT */
/*
 * libtraceeval histogram interface implementation.
 *
 * Copyright (C) 2023 Google Inc, Stevie Alvarez <stevie.6strings@gmail.com>
 */

#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include <traceeval-hist.h>

#include "traceeval-test.h"

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

/* A key-value pair */
struct entry {
	union traceeval_data	*keys;
	union traceeval_data	*vals;
};

/* A table of key-value entries */
struct hist_table {
	struct entry	*map;
	size_t		nr_entries;
};

/* Histogram */
struct traceeval {
	struct traceeval_type		*key_types;
	struct traceeval_type		*val_types;
	struct hist_table		*hist;
	size_t				nr_key_types;
	size_t				nr_val_types;
};

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
 * Compare traceeval_type instances for equality.
 *
 * Return 1 if @orig and @copy are the same, 0 otherwise.
 */
static int compare_traceeval_type(struct traceeval_type *orig,
				  struct traceeval_type *copy,
				  size_t orig_size, size_t copy_size)
{
	size_t i;

	/* same memory/NULL */
	if (orig == copy)
		return 1;
	if (!!orig != !!copy)
		return 0;

	if (orig_size != copy_size)
		return 0;

	for (i = 0; i < orig_size; i++) {
		if (orig[i].type != copy[i].type)
			return 0;
		if (orig[i].flags != copy[i].flags)
			return 0;
		if (orig[i].id != copy[i].id)
			return 0;
		if (orig[i].dyn_release != copy[i].dyn_release)
			return 0;
		if (orig[i].dyn_cmp != copy[i].dyn_cmp)
			return 0;

		// make sure both names are same type
		if (!!orig[i].name != !!copy[i].name)
			return 0;
		if (!orig[i].name)
			continue;
		if (strcmp(orig[i].name, copy[i].name) != 0)
			return 0;
	}

	return 1;
}

/*
 * Compare traceeval_data instances.
 *
 * Return 0 if @orig and @copy are the same, 1 if @orig is greater than @copy,
 * -1 for the other way around, and -2 on error.
 */
static int compare_traceeval_data(union traceeval_data *orig,
				  const union traceeval_data *copy,
				  struct traceeval_type *type)
{
	int i;

	if (orig == copy)
		return 0;

	if (!orig)
		return -1;

	if (!copy)
		return 1;

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
		if (type->dyn_cmp)
			return type->dyn_cmp(orig->dyn_data, copy->dyn_data, type);
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
static int compare_traceeval_data_set(union traceeval_data *orig,
				      const union traceeval_data *copy,
				      struct traceeval_type *defs, size_t size)
{
	int check;
	size_t i;

	/* compare data arrays */
	for (i = 0; i < size; i++) {
		if ((check = compare_traceeval_data(orig + i, copy + i, defs + i)))
			return check == -2 ? -1 : 0;
	}

	return 1;
}

/*
 * Return 1 if @orig and @copy are the same, 0 if not, and -1 on error.
 */
static int compare_entries(struct entry *orig, struct entry *copy,
			   struct traceeval *teval)
{
	int check;

	/* compare keys */
	check = compare_traceeval_data_set(orig->keys, copy->keys,
			teval->key_types, teval->nr_key_types);
	if (check < 1)
		return check;

	/* compare values */
	check = compare_traceeval_data_set(orig->vals, copy->vals,
			teval->val_types, teval->nr_val_types);
	return check;
}

/*
 * Compares the hist fields of @orig and @copy for equality.
 *
 * Assumes all other aspects of @orig and @copy are the same.
 *
 * Return 1 if struct hist_table of @orig and @copy are the same, 0 if not,
 * and -1 on error.
 */
static int compare_hist(struct traceeval *orig, struct traceeval *copy)
{
	struct hist_table *o_hist;
	struct hist_table *c_hist;
	int c;

	o_hist = orig->hist;
	c_hist = copy->hist;

	if (o_hist->nr_entries != c_hist->nr_entries)
		return 0;

	for (size_t i = 0; i < o_hist->nr_entries; i++) {
		if ((c = compare_entries(o_hist->map + i, c_hist->map + i, orig)) < 1)
			return c;
	}

	return 1;
}

/*
 * traceeval_compare - Check equality between two traceeval instances
 * @orig: The first traceeval instance
 * @copy: The second traceeval instance
 *
 * This compares the values of the key definitions, value definitions, and
 * inserted data between @orig and @copy in order. It does not compare
 * by memory address, except for struct traceeval_type's dyn_release() and
 * dyn_cmp() fields.
 *
 * Returns 1 if @orig and @copy are the same, 0 if not, and -1 on error.
 */
 int traceeval_compare(struct traceeval *orig, struct traceeval *copy)
{
	int keys;
	int vals;
	int hists;

	if (!orig || !copy)
		return -1;

	keys = compare_traceeval_type(orig->key_types, copy->key_types,
			orig->nr_key_types, copy->nr_key_types);
	vals = compare_traceeval_type(orig->val_types, copy->val_types,
			orig->nr_val_types, copy->nr_val_types);
	hists = compare_hist(orig, copy);

	if (hists == -1)
		return -1;

	return keys && vals && hists;
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
 * The @keys and @vals passed in are copied for internal use.
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
struct traceeval *traceeval_init(const struct traceeval_type *keys,
				 const struct traceeval_type *vals)
{
	struct traceeval *teval;
	char *err_msg;

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
	teval->hist = calloc(1, sizeof(*teval->hist));
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
		switch (type->type) {
		case TRACEEVAL_TYPE_STRING:
			free(data->string);
			break;
		case TRACEEVAL_TYPE_DYNAMIC:
			if (type->dyn_release)
				type->dyn_release(type, data->dyn_data);
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

	for (i = 0; i < size; i++) {
		clean_data(data + i, defs + i);
	}

	free(data);
}

/*
 * Free all possible data stored within the entry.
 */
static void clean_entry(struct entry *entry, struct traceeval *teval)
{
	if (!entry)
		return;

	/* free dynamic traceeval_data */
	clean_data_set(entry->keys, teval->key_types, teval->nr_key_types);
	clean_data_set(entry->vals, teval->val_types, teval->nr_val_types);
}

/*
 * Free the hist_table allocated to a traceeval instance.
 */
static void hist_table_release(struct traceeval *teval)
{
	struct hist_table *hist = teval->hist;

	if (!hist)
		return;

	for (size_t i = 0; i < hist->nr_entries; i++) {
		clean_entry(hist->map + i, teval);
	}

	free(hist->map);
	free(hist);
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
 * corresponding dyn_release() functions registered for keys and values of
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

/*
 * Find the entry that @keys corresponds to within @teval.
 *
 * Returns 1 on success, 0 if no match found, -1 on error.
 */
static int get_entry(struct traceeval *teval, const union traceeval_data *keys,
		     struct entry **result)
{
	struct hist_table *hist;
	struct entry *entry;
	int check = 0;
	int i;

	if (!teval || !keys)
		return -1;

	hist = teval->hist;
	for (i = 0, entry = hist->map; i < hist->nr_entries; entry = &hist->map[++i]) {
		check = compare_traceeval_data_set(entry->keys, keys,
				teval->key_types, teval->nr_key_types);

		if (!check)
			continue;
		break;
	}

	if (check > 0)
		*result = entry;
	return check;
}

/*
 * Copy @orig to @copy with respect to @type.
 *
 * Return 0 on success, -1 on error.
 */
static int copy_traceeval_data(struct traceeval_type *type,
				const union traceeval_data *orig,
				union traceeval_data *copy)
{
	*copy = *orig;

	if (type->type == TRACEEVAL_TYPE_STRING) {
		copy->string = NULL;

		if (orig->string)
			copy->string = strdup(orig->string);
		else
			return 0;

		if (!copy->string)
			return -1;
	}

	return 0;
}

/*
 * Free @data with respect to @size and @type.
 *
 * Does not call dyn_release on type TRACEEVAL_TYPE_DYNAMIC.
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
 * Copy @orig to @copy with respect to @size and @type.
 *
 * Returns 1 on success, -1 on error.
 */
static int copy_traceeval_data_set(size_t size, struct traceeval_type *type,
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
		if (copy_traceeval_data(type + i, orig + i, (*copy) + i))
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
	return copy_traceeval_data_set(teval->nr_val_types, teval->val_types,
			entry->vals, results);
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
		if (!results)
			print_err("Results to be freed without accompanied traceeval instance!");
		return;
	}

	data_release(teval->nr_val_types, &results, teval->val_types);
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
	struct entry *tmp_map;
	struct hist_table *hist = teval->hist;

	/* copy keys */
	if (copy_traceeval_data_set(teval->nr_key_types, teval->key_types,
				keys, &new_keys) == -1)
		return -1;

	/* copy vals */
	if (copy_traceeval_data_set(teval->nr_val_types, teval->val_types,
				vals, &new_vals) == -1)
		goto fail_vals;

	/* create new entry */
	tmp_map = realloc(hist->map, ++hist->nr_entries * sizeof(*tmp_map));
	if (!tmp_map)
		goto fail;
	tmp_map->keys = new_keys;
	tmp_map->vals = new_vals;
	hist->map = tmp_map;

	return 0;

fail:
	data_release(teval->nr_val_types, &new_vals, teval->val_types);

fail_vals:
	data_release(teval->nr_key_types, &new_keys, teval->key_types);
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

	if (copy_traceeval_data_set(teval->nr_val_types, teval->val_types,
				vals, &new_vals) == -1)
		return -1;

	clean_data_set(entry->vals, teval->val_types, teval->nr_val_types);
	entry->vals = new_vals;
	return 0;
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
