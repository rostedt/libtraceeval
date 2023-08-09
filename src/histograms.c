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
