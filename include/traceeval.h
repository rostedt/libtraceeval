/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#ifndef __LIBTRACEEVAL_H__
#define __LIBTRACEEVAL_H__

#include <stdlib.h>
#include <stdbool.h>

typedef unsigned long long u64;
typedef unsigned int u32;

struct traceeval;
struct traceeval_key_array;
struct traceeval_key_info_array;
struct traceeval_outliers;

enum traceeval_type {
	TRACEEVAL_TYPE_NONE,
	TRACEEVAL_TYPE_STRING,
	TRACEEVAL_TYPE_POINTER,
	TRACEEVAL_TYPE_NUMBER,
	TRACEEVAL_TYPE_NUMBER_64,
	TRACEEVAL_TYPE_NUMBER_32,
	TRACEEVAL_TYPE_NUMBER_16,
	TRACEEVAL_TYPE_NUMBER_8,
	TRACEEVAL_TYPE_ARRAY,
	TRACEEVAL_TYPE_MAX
};

struct traceeval_key_info {
	enum traceeval_type	type;
	size_t			size;
	ssize_t			count;
	const char		*name;
};

struct traceeval_key {
	enum traceeval_type	type;
	ssize_t			count;
	union {
		const char	*string;
		void   		*pointer;
		long		number;
		u64		number_64;
		u32		number_32;
		unsigned short	number_16;
		unsigned char	number_8;
		void		*array;
	};
};

struct traceeval_key_info_array *traceeval_key_info_array_alloc(void);
void traceeval_key_info_array_free(struct traceeval_key_info_array *iarray);
int traceeval_key_info_array_add(struct traceeval_key_info_array *iarray,
				 struct traceeval_key_info *key);

struct traceeval *traceeval_n_alloc(const char *name,
				    const struct traceeval_key_info_array *iarray);
void traceeval_free(struct traceeval *teval);

int traceeval_n_start(struct traceeval *teval, const struct traceeval_key *keys,
		      unsigned long long start);
int traceeval_n_stop(struct traceeval *teval, const struct traceeval_key *keys,
		     unsigned long long stop);
int traceeval_n_continue(struct traceeval *teval, const struct traceeval_key *keys,
			 unsigned long long start);

int traceeval_n_set_private(struct traceeval *teval, const struct traceeval_key *keys,
			    void *data);

void *traceeval_n_get_private(struct traceeval *teval, const struct traceeval_key *keys);

struct traceeval_result_array *traceeval_results(struct traceeval *teval);

size_t traceeval_result_nr(struct traceeval *teval);

size_t traceeval_key_array_nr(struct traceeval_key_array *karray);
const struct traceeval_key *traceeval_key_array_indx(const struct traceeval_key_array *karray,
						     size_t index);
struct traceeval_key_array *traceeval_result_indx_key_array(struct traceeval *teval,
							    size_t index);
ssize_t traceeval_result_indx_cnt(struct traceeval *teval, size_t index);
ssize_t traceeval_result_indx_total(struct traceeval *teval, size_t index);
ssize_t traceeval_result_indx_max(struct traceeval *teval, size_t index);
ssize_t traceeval_result_indx_min(struct traceeval *teval, size_t index);

ssize_t traceeval_result_keys_cnt(struct traceeval *teval, const struct traceeval_key *keys);
ssize_t traceeval_result_keys_total(struct traceeval *teval, const struct traceeval_key *keys);
ssize_t traceeval_result_keys_max(struct traceeval *teval, const struct traceeval_key *keys);
ssize_t traceeval_result_keys_min(struct traceeval *teval, const struct traceeval_key *keys);

struct traceeval *traceeval_1_alloc(const char *name, struct traceeval_key_info info[1]);
int traceeval_1_start(struct traceeval *teval, struct traceeval_key key,
		      unsigned long long start);
int traceeval_1_set_private(struct traceeval *teval, struct traceeval_key key,
			    void *data);
void *traceeval_1_get_private(struct traceeval *teval, struct traceeval_key key);
int traceeval_1_stop(struct traceeval *teval, struct traceeval_key key,
		     unsigned long long stop);
int traceeval_1_continue(struct traceeval *teval, struct traceeval_key key,
			 unsigned long long start);

struct traceeval *traceeval_2_alloc(const char *name, struct traceeval_key_info kinfo[2]);

int traceeval_sort_totals(struct traceeval *teval, bool ascending);
int traceeval_sort_max(struct traceeval *teval, bool ascending);
int traceeval_sort_min(struct traceeval *teval, bool ascending);
int traceeval_sort_cnt(struct traceeval *teval, bool ascending);
int traceeval_sort_keys(struct traceeval *teval, bool ascending);

typedef int (*traceeval_cmp_func)(struct traceeval *teval,
				  const struct traceeval_key_array *A,
				  const struct traceeval_key_array *B,
				  void *data);

int traceeval_sort_custom(struct traceeval *teval, traceeval_cmp_func cmp, void *data);

#endif /* __LIBTRACEEVAL_H__ */
