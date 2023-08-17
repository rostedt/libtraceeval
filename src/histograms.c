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

/* A hash of key-value entries */
struct hash_table {
	struct hash_item	**hash;
	unsigned		bits;
	size_t			nr_items;
};

/* A key-value pair */
struct entry {
	struct hash_item	hash;
	union traceeval_data	*keys;
	union traceeval_data	*vals;
};

/* Histogram */
struct traceeval {
	struct traceeval_type		*key_types;
	struct traceeval_type		*val_types;
	struct hash_table		*hist;
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
	teval->hist->bits = HASH_BITS;
	teval->hist->hash = calloc(HASH_SIZE(teval->hist->bits),
				   sizeof(*teval->hist->hash));
	if (!teval->hist->hash)
		goto fail_release;

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

static void free_entries(struct traceeval *teval, struct hash_item *item)
{
	struct entry *entry;

	while (item) {
		entry = container_of(item, struct entry, hash);
		item = item->next;
		free_entry(teval, entry);
	}
}

/*
 * Free the hist_table allocated to a traceeval instance.
 */
static void hist_table_release(struct traceeval *teval)
{
	struct hash_table *hist = teval->hist;

	if (!hist)
		return;

	for (size_t i = 0; i < HASH_SIZE(hist->bits); i++) {
		if (!hist->hash[i])
			continue;

		free_entries(teval, hist->hash[i]);
	}

	free(hist->hash);
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

static unsigned long long hash_string(const char *str)
{
	unsigned long long key = 0;
	int len = strlen(str);
	int i;

	for (i = 0; i < len; i++)
		key += (unsigned long long)str[i] << ((i & 7) * 8);

	return key;
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
 /*
 * This is a quick hashing function adapted from Donald E. Knuth's 32
 * bit multiplicative hash. See The Art of Computer Programming (TAOCP).
 * Multiplication by the Prime number, closest to the golden ratio of
 * 2^32.
 */
		key += val * 2654435761;
	}

	return key & HASH_MASK(bits);
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
	struct entry *entry;
	unsigned key;
	int check = 0;

	if (!teval || !keys)
		return -1;

	key = make_hash(teval, keys, hist->bits);

	hist = teval->hist;

	for (struct hash_item *item = hist->hash[key]; item; item = item->next) {
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
				union traceeval_data *dst,
				const union traceeval_data *src)
{
	*dst = *src;

	if (type->type == TRACEEVAL_TYPE_STRING) {
		dst->string = NULL;

		if (src->string)
			dst->string = strdup(src->string);
		else
			return 0;

		if (!dst->string)
			return -1;
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
		if (copy_traceeval_data(type + i, (*copy) + i, orig + i))
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
	struct hash_item *item;
	unsigned key = make_hash(teval, keys, hist->bits);
	struct entry *entry;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return NULL;

	item = &entry->hash;
	item->next = hist->hash[key];
	hist->hash[key] = item;
	item->key = key;

	hist->nr_items++;

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

	/* copy keys */
	if (dup_traceeval_data_set(teval->nr_key_types, teval->key_types,
				   keys, &new_keys) == -1)
		return -1;

	/* copy vals */
	if (dup_traceeval_data_set(teval->nr_val_types, teval->val_types,
				   vals, &new_vals) == -1)
		goto fail_vals;

	entry = create_hist_entry(teval, keys);
	if (!entry)
		goto fail;

	entry->keys = new_keys;
	entry->vals = new_vals;

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

	if (dup_traceeval_data_set(teval->nr_val_types, teval->val_types,
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
