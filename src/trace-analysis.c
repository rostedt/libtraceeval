// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#include <string.h>
#include <errno.h>
#include <traceeval.h>

enum sort_type {
	KEYS,
	TOTALS,
	MAX,
	MIN,
	CNT,
};

struct traceeval_key_info_array {
	size_t				nr_keys;
	struct traceeval_key_info	*keys;
};

struct eval_instance {
	unsigned long long	total;
	unsigned long long	last;
	unsigned long long	max;
	unsigned long long	min;
	unsigned long long	cnt;
	size_t			nr_keys;
	struct traceeval_key	*keys;
	void			*private;
};

struct traceeval {
	struct traceeval_key_info_array		array;
	struct eval_instance			*evals;
	size_t					nr_evals;
	struct eval_instance			*results;
	enum sort_type				sort_type;
};

struct traceeval_result_array {
	int				nr_results;
	struct traceeval_result		*results;
};

struct traceeval_key_info_array *traceeval_key_info_array_alloc(void)
{
	struct traceeval_key_info_array *tarray;

	tarray = calloc(1, sizeof(*tarray));
	return tarray;
}

void traceeval_key_info_array_free(struct traceeval_key_info_array *tarray)
{
	if (!tarray)
		return;

	free(tarray->keys);
	free(tarray);
}

int traceeval_key_info_array_add(struct traceeval_key_info_array *tarray,
				 struct traceeval_key_info *key)
{
	size_t nr = tarray->nr_keys;
	struct traceeval_key_info *kinfo;

	kinfo = realloc(tarray->keys, sizeof(*kinfo) * (nr + 1));
	if (!kinfo)
		return -1;

	tarray->keys = kinfo;
	tarray->nr_keys++;
	tarray->keys[nr] = *key;

	return 0;
}

struct traceeval *
traceeval_n_alloc(const char *name, const struct traceeval_key_info_array *keys)
{
	struct traceeval *teval;
	int i;

	teval = calloc(1, sizeof(*teval));
	if (!teval)
		return NULL;

	teval->array.keys = calloc(keys->nr_keys, sizeof(*keys->keys));
	if (!teval->array.keys)
		goto fail;

	teval->array.nr_keys = keys->nr_keys;

	for (i = 0; i < keys->nr_keys; i++)
		teval->array.keys[i] = keys->keys[i];

	return teval;
 fail:
	free(teval);
	return NULL;
}

void traceeval_free(struct traceeval *teval)
{
	if (!teval)
		return;

	free(teval->array.keys);
	free(teval->evals);
	free(teval);
}

static int cmp_keys(struct traceeval_key_info_array *tarray,
		    struct traceeval_key *A, struct traceeval_key *B, int *err)
{
	struct traceeval_key_info *kinfo;
	unsigned long long A_val, B_val;
	int ret;
	int i;

	for (i = 0; i < tarray->nr_keys; i++) {
		kinfo = &tarray->keys[i];

		/* TBD arrays */
		if (kinfo->count) {
			*err = 1;
			return -1;
		}

		if (A[i].type != kinfo->type ||
		    B[i].type != kinfo->type) {
			*err = 1;
			return -1;
		}

		switch (kinfo->type) {
		case TRACEEVAL_TYPE_STRING:
			ret = strcmp(A[i].string, B[i].string);
			if (ret)
				return ret;
			continue;

		case TRACEEVAL_TYPE_NUMBER:
			A_val = A[i].number;
			B_val = B[i].number;
			break;
		case TRACEEVAL_TYPE_NUMBER_64:
			A_val = A[i].number_64;
			B_val = B[i].number_64;
			break;
		case TRACEEVAL_TYPE_NUMBER_32:
			A_val = A[i].number_32;
			B_val = B[i].number_32;
			break;
		case TRACEEVAL_TYPE_NUMBER_16:
			A_val = A[i].number_16;
			B_val = B[i].number_16;
			break;
		case TRACEEVAL_TYPE_NUMBER_8:
			A_val = A[i].number_8;
			B_val = B[i].number_8;
			break;
		case TRACEEVAL_TYPE_ARRAY:
		default:
			*err = 1;
			return -1;
		}
		if (A_val > B_val)
			return 1;
		if (A_val < B_val)
			return -1;
	}
	return 0;
}

static struct eval_instance *
_find_eval_instance(struct traceeval *teval, struct traceeval_key *keys,
		   int *B, int *E, int *N, int *err)
{
	struct eval_instance *eval = NULL;
	int b, e, n;
	int ret;

	b = n = 0;
	e = teval->nr_evals - 1;

	while (b <= e) {
		n = (b + e) / 2;
		eval = &teval->evals[n];
		ret = cmp_keys(&teval->array, keys, eval->keys, err);
		if (ret > 0) {
			b = n + 1;
		} else if (ret < 0) {
			if (*err) {
				errno = EINVAL;
				return NULL;
			}
			e = n - 1;
		} else
			break;
	}

	*B = b;
	*E = e;
	*N = n;

	return eval;
}

static void free_results (struct traceeval *teval)
{
	free(teval->results);
	teval->results = NULL;
}

static struct eval_instance *
get_eval_instance(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_instance *eval;
	int b, e, n;
	int err = 0;

	eval = _find_eval_instance(teval, keys, &b, &e, &n, &err);
	if (err)
		return NULL;

	if (b > e) {
		eval = realloc(teval->evals, sizeof(*eval) * (teval->nr_evals + 1));
		if (!eval)
			return NULL;

		teval->evals = eval;

		if (n != teval->nr_evals)
			memmove(&teval->evals[n+1], &teval->evals[n],
				(sizeof(*eval) * (teval->nr_evals - n)));
		eval = &teval->evals[n];
		memset(eval, 0, sizeof(*eval));
		eval->keys = calloc(teval->array.nr_keys, sizeof(*eval->keys));
		if (!eval->keys)
			return NULL;
		for (b = 0; b < teval->array.nr_keys; b++)
			eval->keys[b] = keys[b];
		eval->nr_keys = teval->array.nr_keys;
		teval->nr_evals++;

		/*
		 * Results are a copy of evals, it is no longer reliable
		 * after a realloc, and is not sorted the same.
		 */
		free_results(teval);
	}

	return eval;
}

static struct eval_instance *
find_eval_instance(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_instance *eval;
	int b, e, n;
	int err = 0;

	eval = _find_eval_instance(teval, keys, &b, &e, &n, &err);
	if (err)
		return NULL;

	return b > e ? NULL : eval;
}

int traceeval_n_start(struct traceeval *teval, struct traceeval_key *keys,
		      unsigned long long start)
{
	struct eval_instance *eval;

	eval = get_eval_instance(teval, keys);
	if (!eval)
		return -1;

	eval->last = start;
	return 0;
}

int traceeval_n_continue(struct traceeval *teval, struct traceeval_key *keys,
			 unsigned long long start)
{
	struct eval_instance *eval;

	eval = get_eval_instance(teval, keys);
	if (!eval)
		return -1;

	if (eval->last)
		return 0;

	eval->last = start;
	return 0;
}

int traceeval_n_set_private(struct traceeval *teval, struct traceeval_key *keys,
			    void *data)
{
	struct eval_instance *eval;

	/* Setting an instance forces a creation of it */
	eval = get_eval_instance(teval, keys);
	if (!eval)
		return -1;

	eval->private = data;
	return 0;
}

void *traceeval_n_get_private(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_instance *eval;

	eval = find_eval_instance(teval, keys);
	if (!eval)
		return NULL;

	return eval->private;
}

int traceeval_n_stop(struct traceeval *teval, struct traceeval_key *keys,
		     unsigned long long stop)
{
	struct eval_instance *eval;
	unsigned long long delta;

	eval = get_eval_instance(teval, keys);
	if (!eval)
		return -1;

	if (!eval->last)
		return 1;

	delta = stop - eval->last;
	eval->total += delta;
	if (!eval->min || eval->min > delta)
		eval->min = delta;
	if (eval->max < delta)
		eval->max = delta;
	eval->cnt++;

	eval->last = 0;

	return 0;
}

size_t traceeval_result_nr(struct traceeval *teval)
{
	return teval->nr_evals;
}

size_t traceeval_key_array_nr(struct traceeval_key_array *karray)
{
	struct eval_instance *eval = (struct eval_instance *)karray;

	if (!karray)
		return 0;

	return eval->nr_keys;
}

const struct traceeval_key *
traceeval_key_array_indx(struct traceeval_key_array *karray, size_t index)
{
	struct eval_instance *eval = (struct eval_instance *)karray;

	if (!karray || index >= eval->nr_keys)
		return NULL;

	return &eval->keys[index];
}

static struct eval_instance *get_result(struct traceeval *teval, size_t index)
{
	if (index >= teval->nr_evals)
		return NULL;

	if (teval->results)
		return &teval->results[index];
	return &teval->evals[index];
}

struct traceeval_key_array *
traceeval_result_indx_key_array(struct traceeval *teval, size_t index)
{
	struct eval_instance *eval = get_result(teval, index);

	if (!eval)
		return NULL;

	return (struct traceeval_key_array *)eval;
}

ssize_t
traceeval_result_indx_cnt(struct traceeval *teval, size_t index)
{
	struct eval_instance *eval = get_result(teval, index);

	if (!eval)
		return -1;

	return eval->cnt;
}

ssize_t
traceeval_result_indx_total(struct traceeval *teval, size_t index)
{
	struct eval_instance *eval = get_result(teval, index);

	if (!eval)
		return -1;

	return eval->total;
}

ssize_t
traceeval_result_indx_max(struct traceeval *teval, size_t index)
{
	struct eval_instance *eval = get_result(teval, index);

	if (!eval)
		return -1;

	return eval->max;
}

ssize_t
traceeval_result_indx_min(struct traceeval *teval, size_t index)
{
	struct eval_instance *eval = get_result(teval, index);

	if (!eval)
		return -1;

	return eval->min;
}


ssize_t
traceeval_result_keys_cnt(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_instance *eval;

	eval = find_eval_instance(teval, keys);
	if (!eval)
		return -1;

	return eval->cnt;
}

ssize_t
traceeval_result_keys_total(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_instance *eval;

	eval = find_eval_instance(teval, keys);
	if (!eval)
		return -1;

	return eval->total;
}

ssize_t
traceeval_result_keys_max(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_instance *eval;

	eval = find_eval_instance(teval, keys);
	if (!eval)
		return -1;

	return eval->max;
}

ssize_t
traceeval_result_keys_min(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_instance *eval;

	eval = find_eval_instance(teval, keys);
	if (!eval)
		return -1;

	return eval->min;
}

struct traceeval *
traceeval_1_alloc(const char *name, struct traceeval_key_info kinfo[1])
{
	struct traceeval_key_info_array karray = {
		.nr_keys = 1,
		.keys = kinfo,
	};

	return traceeval_n_alloc(name, &karray);
}

int traceeval_1_start(struct traceeval *teval, struct traceeval_key key,
		      unsigned long long start)
{
	struct traceeval_key keys[1] = { key };

	return traceeval_n_start(teval, keys, start);
}

int traceeval_1_continue(struct traceeval *teval, struct traceeval_key key,
			 unsigned long long start)
{
	struct traceeval_key keys[1] = { key };

	return traceeval_n_continue(teval, keys, start);
}

int traceeval_1_set_private(struct traceeval *teval, struct traceeval_key key,
			    void *data)
{
	struct traceeval_key keys[1] = { key };

	return traceeval_n_set_private(teval, keys, data);
}

void *traceeval_1_get_private(struct traceeval *teval, struct traceeval_key key)
{
	struct traceeval_key keys[1] = { key };

	return traceeval_n_get_private(teval, keys);
}

int traceeval_1_stop(struct traceeval *teval, struct traceeval_key key,
		     unsigned long long stop)
{
	struct traceeval_key keys[1] = { key };

	return traceeval_n_stop(teval, keys, stop);
}

struct traceeval *
traceeval_2_alloc(const char *name, struct traceeval_key_info kinfo[2])
{
	struct traceeval_key_info_array karray = {
		.nr_keys = 2,
		.keys = kinfo,
	};

	return traceeval_n_alloc(name, &karray);
}

static int create_results(struct traceeval *teval)
{
	int i;

	if (teval->results)
		return 0;

	teval->results = calloc(teval->nr_evals, sizeof(*teval->results));
	if (!teval->results)
		return -1;
	for (i = 0; i < teval->nr_evals; i++)
		teval->results[i] = teval->evals[i];

	return 0;
}

static int cmp_totals(const void *A, const void *B)
{
	const struct eval_instance *a = A;
	const struct eval_instance *b = B;

	if (a->total < b->total)
		return -1;
	return a->total > b->total;
}

static int cmp_max(const void *A, const void *B)
{
	const struct eval_instance *a = A;
	const struct eval_instance *b = B;

	if (a->max < b->max)
		return -1;
	return a->max > b->max;
}

static int cmp_min(const void *A, const void *B)
{
	const struct eval_instance *a = A;
	const struct eval_instance *b = B;

	if (a->min < b->min)
		return -1;
	return a->min > b->min;
}

static int cmp_cnt(const void *A, const void *B)
{
	const struct eval_instance *a = A;
	const struct eval_instance *b = B;

	if (a->cnt < b->cnt)
		return -1;
	return a->cnt > b->cnt;
}

static int cmp_inverse(const void *A, const void *B, void *cmp)
{
	int (*cmp_func)(const void *, const void *) = cmp;

	return cmp_func(B, A);
}

static int eval_sort(struct traceeval *teval, enum sort_type sort_type, bool ascending)
{
	int (*cmp_func)(const void *, const void *);

	if (create_results(teval) < 0)
		return -1;

	if (teval->sort_type == sort_type)
		return 0;

	switch (sort_type) {
	case TOTALS:
		cmp_func = cmp_totals;
		break;
	case MAX:
		cmp_func = cmp_max;
		break;
	case MIN:
		cmp_func = cmp_min;
		break;
	case CNT:
		cmp_func = cmp_cnt;
		break;
	case KEYS:
		return 0;
	}

	if (ascending)
		qsort(teval->results, teval->nr_evals, sizeof(*teval->results), cmp_func);
	else
		qsort_r(teval->results, teval->nr_evals, sizeof(*teval->results),
			cmp_inverse, cmp_func);
	teval->sort_type = sort_type;
	return 0;
}

int traceeval_sort_totals(struct traceeval *teval, bool ascending)
{
	return eval_sort(teval, TOTALS, ascending);
}

int traceeval_sort_max(struct traceeval *teval, bool ascending)
{
	return eval_sort(teval, MAX, ascending);
}

int traceeval_sort_min(struct traceeval *teval, bool ascending)
{
	return eval_sort(teval, MIN, ascending);
}

int traceeval_sort_cnt(struct traceeval *teval, bool ascending)
{
	return eval_sort(teval, CNT, ascending);
}

int traceeval_sort_keys(struct traceeval *teval, bool ascending)
{
	int i, nr;

	if (ascending) {
		/* evals are sorted by keys */
		free_results(teval);
		teval->sort_type = KEYS;
		return 0;
	}

	if (create_results(teval) < 0)
		return -1;

	nr = teval->nr_evals - 1;

	/* Just invert the evals */
	for (i = 0; i <= nr; i++)
		teval->results[i] = teval->evals[nr - i];

	return 0;
}
