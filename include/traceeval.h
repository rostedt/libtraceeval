/* SPDX-License-Identifier: MIT */
/*
 * libtraceeval histogram interface.
 *
 * Copyright (C) 2022-2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 * Copyright (C) 2023 Google Inc, Stevie Alvarez <stevie.6strings@gmail.com>
 */
#ifndef __LIBTRACEEVAL_HIST_H__
#define __LIBTRACEEVAL_HIST_H__

#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>

/* Data definition interfaces */

/* Field name/descriptor for number of hits */
#define TRACEEVAL_VAL_HITS ((const char *)(-1UL))

/*
 * If your compile failed due to the below macro, it is likely you used
 * a pointer to struct traceeval_data, and not a static array.
 *
 * That is:
 *
 *    struct traceeval_data *keys;
 *
 * and not:
 *
 *    struct traceeval_data keys[] = { ... };
 */
#define __TRACEEVAL_ARRAY_SIZE(data)					\
	((sizeof(data) / (sizeof((data)[0]) + 0)) +			\
	(int)(sizeof(struct {						\
		int:(-!!(__builtin_types_compatible_p(typeof(data),	\
						      typeof(&((data)[0]))) && \
			 (void *)(data) != NULL));			\
			})))

#define TRACEEVAL_ARRAY_SIZE(data) \
	((void *)(data) == NULL ?  0 : __TRACEEVAL_ARRAY_SIZE(data))

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
	TRACEEVAL_TYPE_DELTA,
};

/* Statistics specification flags */
enum traceeval_flags {
	TRACEEVAL_FL_KEY		= (1 << 0),
	TRACEEVAL_FL_VALUE		= (1 << 1),
	TRACEEVAL_FL_SIGNED		= (1 << 2),
	TRACEEVAL_FL_TIMESTAMP		= (1 << 3),
	TRACEEVAL_FL_STAT		= (1 << 4),
};

enum traceeval_log_level {
	TEVAL_NONE		= 0,
	TEVAL_CRIT,
	TEVAL_WARN,
	TEVAL_INFO,
};

extern void traceeval_vwarning(const char *fmt, va_list ap);
extern void traceeval_set_log_level(enum traceeval_log_level level);

struct traceeval_data_delta {
	unsigned long long			delta;
	unsigned long long			timestamp;
};

/*
 * Trace data entry for a traceeval histogram
 * Constitutes keys and values.
 */
struct traceeval_data {
	enum traceeval_data_type		type;
	union {
		char				*string;
		const char			*cstring;
		void				*pointer;
		unsigned long			number;
		unsigned long long		number_64;
		unsigned int			number_32;
		unsigned short			number_16;
		unsigned char			number_8;
		struct traceeval_data_delta	delta;
	};
};

#define __TRACEEVAL_DATA(data_type, member, data)			\
	{  .type = TRACEEVAL_TYPE_##data_type, .member = (data) }

#define DEFINE_TRACEEVAL_NUMBER(data)	   __TRACEEVAL_DATA(NUMBER, number, data)
#define DEFINE_TRACEEVAL_NUMBER_8(data)	   __TRACEEVAL_DATA(NUMBER_8, number_8, data)
#define DEFINE_TRACEEVAL_NUMBER_16(data)   __TRACEEVAL_DATA(NUMBER_16, number_16, data)
#define DEFINE_TRACEEVAL_NUMBER_32(data)   __TRACEEVAL_DATA(NUMBER_32, number_32, data)
#define DEFINE_TRACEEVAL_NUMBER_64(data)   __TRACEEVAL_DATA(NUMBER_64, number_64, data)
#define DEFINE_TRACEEVAL_STRING(data)	   __TRACEEVAL_DATA(STRING, string, data)
#define DEFINE_TRACEEVAL_CSTRING(data)	   __TRACEEVAL_DATA(STRING, cstring, data)
#define DEFINE_TRACEEVAL_POINTER(data)	   __TRACEEVAL_DATA(POINTER, pointer, data)

#define DEFINE_TRACEEVAL_DELTA(data, ts) \
	__TRACEEVAL_DATA(DELTA, { .delta = data, .timestamp = ts })

#define __TRACEEVAL_SET(data, data_type, member, val)		\
	do {							\
		(data).type = TRACEEVAL_TYPE_##data_type;	\
		(data).member = (val);				\
	} while (0)

/* Have strings and pointers fail to be set to numbers */
#define __TRACEEVAL_SET_NUM(data, data_type, member, val)	\
	do {							\
		char *__test__[val] __attribute__((unused));	\
		__TRACEEVAL_SET(data, data_type, member, val);	\
	} while (0)

/* Have numbers fail to be assigned as strings */
#define __TRACEEVAL_SET_STR(data, data_type, member, val)		\
	do {								\
		char __test__  __attribute__((unused)) = (val)[0];	\
		__TRACEEVAL_SET(data, data_type, member, val);		\
	} while (0)

#define TRACEEVAL_SET_NUMBER(data, val)	     __TRACEEVAL_SET_NUM(data, NUMBER, number, val)
#define TRACEEVAL_SET_NUMBER_8(data, val)    __TRACEEVAL_SET_NUM(data, NUMBER_8, number_8, val)
#define TRACEEVAL_SET_NUMBER_16(data, val)   __TRACEEVAL_SET_NUM(data, NUMBER_16, number_16, val)
#define TRACEEVAL_SET_NUMBER_32(data, val)   __TRACEEVAL_SET_NUM(data, NUMBER_32, number_32, val)
#define TRACEEVAL_SET_NUMBER_64(data, val)   __TRACEEVAL_SET_NUM(data, NUMBER_64, number_64, val)
#define TRACEEVAL_SET_STRING(data, val)	     __TRACEEVAL_SET_STR(data, STRING, string, val)
#define TRACEEVAL_SET_CSTRING(data, val)     __TRACEEVAL_SET_STR(data, STRING, cstring, val)
#define TRACEEVAL_SET_POINTER(data, val)     __TRACEEVAL_SET(data, POINTER, pointer, val)

#define TRACEEVAL_SET_DELTA(data, val_delta, val_ts)		\
	do {							\
		(data).type = TRACEEVAL_TYPE_DELTA;		\
		(data).delta.delta = (val_delta);		\
		(data).delta.timestamp = (val_ts);		\
	} while (0)

struct traceeval_type;
struct traceeval;

/* release function callback on traceeval_data */
typedef void (*traceeval_data_release_fn)(const struct traceeval_type *type,
					  struct traceeval_data *data);

/* compare function callback to compare traceeval_data */
typedef int (*traceeval_data_cmp_fn)(struct traceeval *teval,
				     const struct traceeval_type *type,
				     const struct traceeval_data *A,
				     const struct traceeval_data *B);

/* make a unique value */
typedef int (*traceeval_data_hash_fn)(struct traceeval *teval,
				      const struct traceeval_type *type,
				      const struct traceeval_data *data);

typedef int (*traceeval_data_copy_fn)(const struct traceeval_type *type,
				      struct traceeval_data *dst,
				      const struct traceeval_data *src);

typedef int (*traceeval_cmp_fn)(struct traceeval *teval,
				const struct traceeval_data *Akeys,
				const struct traceeval_data *Avals,
				const struct traceeval_data *Bkeys,
				const struct traceeval_data *Bvals,
				void *data);

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
 * traceeval_type instances and needs to distinguish between them into
 * 'sub-types'.
 *
 * For flexibility, @cmp() and @release() take a struct traceeval_type
 * instance. This allows the user to handle pointer types.
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
 * required to pointer types. It should return 0 on equality, 1 if the first
 * argument is greater than the second, -1 for the other way around,
 * and -2 on error.
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
	traceeval_data_copy_fn		copy;
	traceeval_data_hash_fn		hash;
};

/* Statistics about a given entry element */
struct traceeval_stat;

/* Iterator over aggregated data */
struct traceeval_iterator;

struct traceeval;

/* Histogram interfaces */

#define traceeval_init(keys, vals)					\
	traceeval_init_size(keys, vals,					\
			    TRACEEVAL_ARRAY_SIZE(keys),			\
			    TRACEEVAL_ARRAY_SIZE(vals))

#define traceeval_init_size(keys, vals, nr_keys, nr_vals)		\
	traceeval_init_data_size(keys, vals, nr_keys, nr_vals,		\
				 sizeof(struct traceeval_type),		\
				 sizeof(struct traceeval_data))

struct traceeval *traceeval_init_data_size(struct traceeval_type *keys,
					   struct traceeval_type *vals,
					   size_t nr_keys, size_t nr_vals,
					   size_t sizeof_type, size_t sizeof_data);

void traceeval_release(struct traceeval *teval);

int traceeval_insert_size(struct traceeval *teval,
			  const struct traceeval_data *keys, size_t nr_keys,
			  const struct traceeval_data *vals, size_t nr_vals);

#define traceeval_insert(teval, keys, vals)				\
	traceeval_insert_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys), \
			      vals, TRACEEVAL_ARRAY_SIZE(vals))

int traceeval_remove_size(struct traceeval *teval,
			  const struct traceeval_data *keys, size_t nr_keys);

#define traceeval_remove(teval, keys)					\
	traceeval_remove_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys))

int traceeval_query_size(struct traceeval *teval, const struct traceeval_data *keys,
			 size_t nr_keys, const struct traceeval_data **results);

#define traceeval_query(teval, keys, results)				\
	traceeval_query_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys), results)

void traceeval_results_release(struct traceeval *teval,
			       const struct traceeval_data *results);

#define traceeval_hitcount(teval, keys)					\
	traceeval_hitcount_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys))

ssize_t traceeval_hitcount_size(struct traceeval *teval,
				const struct traceeval_data *keys, size_t nr_keys);

size_t traceeval_count(struct traceeval *teval);

#define traceeval_delta_create(teval, keys, vals)			\
	traceeval_delta_create_size(teval, keys, vals,			\
				  TRACEEVAL_ARRAY_SIZE(keys),		\
				  TRACEEVAL_ARRAY_SIZE(vals))

#define traceeval_delta_create_size(teval, keys, vals, nr_keys, nr_vals) \
	traceeval_delta_create_data_size(teval, keys, vals, nr_keys, nr_vals, \
				       sizeof(struct traceeval_type),	\
				       sizeof(struct traceeval_data))

int traceeval_delta_create_data_size(struct traceeval *teval,
				     struct traceeval_type *keys,
				     struct traceeval_type *vals,
				     size_t nr_keys, size_t nr_vals,
				     size_t sizeof_type,
				     size_t sizeof_data);

int traceeval_delta_start_size(struct traceeval *teval,
			       const struct traceeval_data *keys, size_t nr_keys,
			       const struct traceeval_data *vals, size_t nr_vals,
			       unsigned long long timestamp);

#define traceeval_delta_start(teval, keys, vals, timestamp)		\
	traceeval_delta_start_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys), \
				   vals, TRACEEVAL_ARRAY_SIZE(vals), timestamp)

int traceeval_delta_query_size(struct traceeval *teval,
			       const struct traceeval_data *keys,
			       size_t nr_keys, const struct traceeval_data **results);

#define traceeval_delta_query(teval, keys, results)			\
	traceeval_delta_query_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys), results)

int traceeval_delta_continue_size(struct traceeval *teval,
				  const struct traceeval_data *keys, size_t nr_keys,
				  const struct traceeval_data *vals, size_t nr_vals,
				  unsigned long long timestamp);

#define traceeval_delta_continue(teval, keys, vals, timestamp)		\
	traceeval_delta_continue_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys), \
				      vals, TRACEEVAL_ARRAY_SIZE(vals), timestamp)

int traceeval_delta_stop_size(struct traceeval *teval,
			      const struct traceeval_data *keys, size_t nr_keys,
			      const struct traceeval_data **results,
			      unsigned long long timestamp,
			      unsigned long long *delta,
			      unsigned long long *start_timestamp);

#define traceeval_delta_stop(teval, keys, results, timestamp, delta, start_ts)		\
	traceeval_delta_stop_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys), \
				  results, timestamp, delta, start_ts)

#define traceeval_stat(teval, keys, val_name)				\
	traceeval_stat_size(teval, keys, TRACEEVAL_ARRAY_SIZE(keys), val_name)

struct traceeval_stat *traceeval_stat_size(struct traceeval *teval,
					   const struct traceeval_data *keys,
					   size_t nr_keys,
					   const char *val_name);

unsigned long long traceeval_stat_max(struct traceeval_stat *stat);
unsigned long long traceeval_stat_min(struct traceeval_stat *stat);
unsigned long long traceeval_stat_total(struct traceeval_stat *stat);
unsigned long long traceeval_stat_count(struct traceeval_stat *stat);
unsigned long long traceeval_stat_max_timestamp(struct traceeval_stat *stat,
						unsigned long long *ts);
unsigned long long traceeval_stat_min_timestamp(struct traceeval_stat *stat,
						unsigned long long *ts);
unsigned long long traceeval_stat_average(struct traceeval_stat *stat);
double traceeval_stat_stddev(struct traceeval_stat *stat);

struct traceeval_iterator *traceeval_iterator_get(struct traceeval *teval);
struct traceeval_iterator *traceeval_iterator_delta_start_get(struct traceeval *teval);
void traceeval_iterator_put(struct traceeval_iterator *iter);
int traceeval_iterator_sort(struct traceeval_iterator *iter, const char *sort_field,
			    int level, bool ascending);
int traceeval_iterator_sort_custom(struct traceeval_iterator *iter,
				   traceeval_cmp_fn sort_fn, void *data);
int traceeval_iterator_next(struct traceeval_iterator *iter,
			    const struct traceeval_data **keys);
int traceeval_iterator_query(struct traceeval_iterator *iter,
			     const struct traceeval_data **results);
void traceeval_iterator_results_release(struct traceeval_iterator *iter,
					const struct traceeval_data *results);
struct traceeval_stat *traceeval_iterator_stat(struct traceeval_iterator *iter,
					       const char *val_name);
int traceeval_iterator_delta_stop(struct traceeval_iterator *iter,
				  const struct traceeval_data **results,
				  unsigned long long timestamp,
				  unsigned long long *delta,
				  unsigned long long *start_ts);
int traceeval_iterator_remove(struct traceeval_iterator *iter);

#endif /* __LIBTRACEEVAL_HIST_H__ */
