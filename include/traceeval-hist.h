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
	TRACEEVAL_TYPE_STRING,
	TRACEEVAL_TYPE_DYNAMIC
};

/* Statistics specification flags */
enum traceeval_flags {
	TRACEEVAL_FL_SIGNED		= (1 << 0),
	TRACEEVAL_FL_TIMESTAMP		= (1 << 1),
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
	unsigned long			number;
	unsigned long long		number_64;
	unsigned int			number_32;
	unsigned short			number_16;
	unsigned char			number_8;
};

struct traceeval_type;

/* struct traceeval_dynamic release function signature */
typedef void (*traceeval_dyn_release_fn)(struct traceeval_type *,
					 struct traceeval_dynamic);

/* struct traceeval_dynamic compare function signature */
typedef int (*traceeval_dyn_cmp_fn)(struct traceeval_dynamic,
				    struct traceeval_dynamic,
				    struct traceeval_type *);

/*
 * struct traceeval_type - Describes the type of a traceevent_data instance
 * @type: The enum type that describes the traceeval_data
 * @name: The string name of the traceeval_data
 * @flags: flags to describe the traceeval_data
 * @id: User specified identifier
 * @dyn_release: For dynamic types called on release (ignored for other types)
 * @dyn_cmp: A way to compare dynamic types (ignored for other types)
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
 * For flexibility, @dyn_cmp() and @dyn_release() take a struct
 * traceeval_type instance. This allows the user to distinguish between
 * different sub-types of struct traceeval_dynamic within a single
 * callback function by examining the @id field. This is not a required
 * approach, merely one that is accommodated.
 *
 * @dyn_cmp() is used to compare two struct traceeval_dynamic instances when a
 * corresponding struct traceeval_type is reached with its type field set to
 * TRACEEVAL_TYPE_DYNAMIC. It should return 0 on equality, 1 if the first
 * argument is greater than the second, -1 for the other way around, and -2 on
 * error.
 *
 * dyn_release() is used during traceeval_release() to release a union
 * traceeval_data's struct traceeval_dynamic field when the corresponding
 * traceeval_type type is set to TRACEEVAL_TYPE_DYNAMIC.
 */
struct traceeval_type {
	char				*name;
	enum traceeval_data_type	type;
	size_t				flags;
	size_t				id;
	traceeval_dyn_release_fn	dyn_release;
	traceeval_dyn_cmp_fn		dyn_cmp;
};

/* Statistics about a given entry element */
struct traceeval_stat {
	unsigned long long	max;
	unsigned long long	min;
	unsigned long long	total;
	unsigned long long	avg;
	unsigned long long	std;
};

/* Iterator over aggregated data */
struct traceeval_iterator;

struct traceeval;

#endif /* __LIBTRACEEVAL_HIST_H__ */
