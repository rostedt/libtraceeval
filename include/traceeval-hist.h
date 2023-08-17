/* SPDX-License-Identifier: MIT */
/*
 * libtraceeval histogram interface.
 *
 * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 * Copyright (C) 2023 Google Inc, Stevie Alvarez <stevie.6strings@gmail.com>
 */
#ifndef __LIBTRACEEVAL_HIST_H__
#define __LIBTRACEEVAL_HIST_H__

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>

/* Data definition interfaces */

/* Field name/descriptor for number of hits */
#define TRACEEVAL_VAL_HITS ((const char *)(-1UL))

/* Data type distinguishers */
enum traceeval_data_type {
	TRACEEVAL_TYPE_NONE,
	TRACEEVAL_TYPE_NUMBER_8,
	TRACEEVAL_TYPE_NUMBER_16,
	TRACEEVAL_TYPE_NUMBER_32,
	TRACEEVAL_TYPE_NUMBER_64,
	TRACEEVAL_TYPE_NUMBER,
	TRACEEVAL_TYPE_POINTER,
	TRACEEVAL_TYPE_STRING,
	TRACEEVAL_TYPE_DYNAMIC
};

/* Statistics specification flags */
enum traceeval_flags {
	TRACEEVAL_FL_KEY		= (1 << 0),
	TRACEEVAL_FL_VALUE		= (1 << 1),
	TRACEEVAL_FL_SIGNED		= (1 << 2),
	TRACEEVAL_FL_TIMESTAMP		= (1 << 3),
};

/*
 * struct traceeval_dynamic - Storage for dynamic traceeval_types
 * @size: The size of the dynamic type
 * @data: The pointer to the data of the dynamic type
 */
struct traceeval_dynamic {
	void		*data;
	size_t		size;
};

/*
 * Trace data entry for a traceeval histogram
 * Constitutes keys and values.
 */
union traceeval_data {
	struct traceeval_dynamic	dyn_data;
	char				*string;
	const char			*cstring;
	void				*pointer;
	unsigned long			number;
	unsigned long long		number_64;
	unsigned int			number_32;
	unsigned short			number_16;
	unsigned char			number_8;
};

struct traceeval_type;
struct traceeval;

/* release function callback on traceeval_data */
typedef void (*traceeval_data_release_fn)(const struct traceeval_type *type,
					  union traceeval_data *data);

/* compare function callback to compare traceeval_data */
typedef int (*traceeval_data_cmp_fn)(struct traceeval *teval,
				     const struct traceeval_type *type,
				     const union traceeval_data *A,
				     const union traceeval_data *B);

/* make a unique value */
typedef int (*traceeval_data_hash_fn)(struct traceeval *teval,
				      const struct traceeval_type *type,
				      const union traceeval_data *data);

/*
 * struct traceeval_type - Describes the type of a traceevent_data instance
 * @type: The enum type that describes the traceeval_data
 * @name: The string name of the traceeval_data
 * @flags: flags to describe the traceeval_data
 * @id: User specified identifier
 * @release: An optional callback for when the data is being released
 * @cmp: An optional callback to specify a way to compare the type
 *
 * The traceeval_type structure defines expectations for a corresponding
 * traceeval_data instance for a traceeval histogram instance. Used to
 * describe both keys and values.
 *
 * The @id field is an optional value in case the user has multiple struct
 * traceeval_type instances with @type fields set to TRACEEVAL_TYPE_DYNAMIC,
 * which each relate to distinct user defined struct traceeval_dynamic
 * 'sub-types'.
 *
 * For flexibility, @cmp() and @release() take a struct traceeval_type
 * instance. This allows the user to handle dyn_data and pointer types.
 * It may also be used for other types if the default cmp() or release()
 * need to be overridden. Note for string types, even if the release()
 * is called, the string freeing is still taken care of by the traceeval
 * infrastructure.
 *
 * The @id field is a user specified field that may allow the same callback
 * to be used by multiple types and not needing to do a strcmp() against the
 * name (could be used for switch statements).
 *
 * @cmp() is used to override the default compare of a type. This is
 * required to compare dyn_data and pointer types. It should return 0
 * on equality, 1 if the first argument is greater than the second,
 * -1 for the other way around, and -2 on error.
 *
 * @release() is called when a data element is being released (or freed).
 */
struct traceeval_type {
	char				*name;
	enum traceeval_data_type	type;
	size_t				flags;
	size_t				index;
	size_t				id;
	traceeval_data_release_fn	release;
	traceeval_data_cmp_fn		cmp;
	traceeval_data_hash_fn		hash;
};

/* Statistics about a given entry element */
struct traceeval_stat;

/* Iterator over aggregated data */
struct traceeval_iterator;

struct traceeval;

/* Histogram interfaces */

struct traceeval *traceeval_init(struct traceeval_type *keys,
				 struct traceeval_type *vals);

void traceeval_release(struct traceeval *teval);

int traceeval_insert(struct traceeval *teval,
		     const union traceeval_data *keys,
		     const union traceeval_data *vals);

int traceeval_query(struct traceeval *teval, const union traceeval_data *keys,
		    union traceeval_data **results);

void traceeval_results_release(struct traceeval *teval,
			       union traceeval_data *results);

struct traceeval_stat *traceeval_stat(struct traceeval *teval,
				      const union traceeval_data *keys,
				      struct traceeval_type *type);

unsigned long long traceeval_stat_max(struct traceeval_stat *stat);
unsigned long long traceeval_stat_min(struct traceeval_stat *stat);
unsigned long long traceeval_stat_total(struct traceeval_stat *stat);
unsigned long long traceeval_stat_count(struct traceeval_stat *stat);

struct traceeval_iterator *traceeval_iterator_get(struct traceeval *teval);
void traceeval_iterator_put(struct traceeval_iterator *iter);
int traceeval_iterator_sort(struct traceeval_iterator *iter, const char *sort_field,
			    int level, bool ascending);
int traceeval_iterator_next(struct traceeval_iterator *iter,
			    const union traceeval_data **keys);

#endif /* __LIBTRACEEVAL_HIST_H__ */
