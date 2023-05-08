// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#include <string.h>
#include <errno.h>
#include <traceeval.h>

#define HASH_BITS 10
#define HASH_SIZE (1 << HASH_BITS)
#define HASH_MASK (HASH_SIZE - 1)

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

struct eval_hash {
	struct eval_hash		*next;
	struct eval_instance		eval;
};

struct traceeval {
	struct traceeval_key_info_array		array;
	struct eval_instance			*evals;
	struct eval_hash			*eval_hash[HASH_SIZE];
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
	struct eval_hash *ehash;
	int i;
	if (!teval)
		return;

	for (i = 0; i < HASH_SIZE; i++) {
		for (ehash = teval->eval_hash[i]; ehash; ) {
			struct eval_hash *tmp = ehash;
			ehash = ehash->next;
			free(tmp);
		}
	}

	free(teval->array.keys);
	free(teval->evals);
	free(teval);
}

static int cmp_keys(struct traceeval_key_info_array *tarray,
		    const struct traceeval_key *A, const struct traceeval_key *B,
		    int *err)
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

static void free_results (struct traceeval *teval)
{
	free(teval->results);
	teval->results = NULL;
}

static int make_key(struct traceeval *teval, struct traceeval_key *keys, int *err)
{
	struct traceeval_key_info *kinfo;
	bool calc;
	int len, l;
	int ret = 0;
	int i;

	for (i = 0; i < teval->array.nr_keys; i++) {
		kinfo = &teval->array.keys[i];

		/* TBD arrays */
		if (kinfo->count) {
			*err = 1;
			return -1;
		}

		if (keys[i].type != kinfo->type) {
			*err = 1;
			return -1;
		}

		calc = false;

		switch (kinfo->type) {
		case TRACEEVAL_TYPE_STRING:
			len = strlen(keys[i].string);

			for (l = 0; l < len; l++) {
				unsigned int c = keys[i].string[l];

				ret += c << ((l & 3) * 8);
			}

			continue;

		case TRACEEVAL_TYPE_NUMBER_32:
			calc = true;
			/* fall though */
		case TRACEEVAL_TYPE_NUMBER:
			if (calc || sizeof(keys[i].number) == 4) {
				ret += keys[i].number;
				continue;
			}
			/* fall through */
		case TRACEEVAL_TYPE_NUMBER_64:
			ret += keys[i].number_64 >> 32;
			ret += keys[i].number_64 & ((1ULL << 32) - 1);
			break;
			break;
		case TRACEEVAL_TYPE_NUMBER_16:
			ret += keys[i].number_16;
			break;
		case TRACEEVAL_TYPE_NUMBER_8:
			ret += keys[i].number_8;
			break;
		case TRACEEVAL_TYPE_ARRAY:
		default:
			*err = 1;
			return -1;
		}
	}
	return ret & HASH_MASK;
}

static struct eval_hash *find_eval(struct traceeval *teval, struct traceeval_key *keys,
				   int *err, int *pkey)
{
	struct eval_hash *ehash;
	int key = make_key(teval, keys, err);

	if (key < 0)
		return NULL;

	if (pkey)
		*pkey = key;

	for (ehash = teval->eval_hash[key]; ehash; ehash = ehash->next) {
		if (cmp_keys(&teval->array, keys, ehash->eval.keys, err) == 0)
			return ehash;
	}
	return NULL;
}

static struct eval_hash *
insert_eval(struct traceeval *teval, struct traceeval_key *keys, int key)
{
	struct eval_instance *eval;
	struct eval_hash *ehash;
	int i;

	ehash = calloc(1, sizeof(*ehash));
	if (!ehash)
		return NULL;

	eval = &ehash->eval;

	eval->keys = calloc(teval->array.nr_keys, sizeof(*eval->keys));
	if (!eval->keys)
		return NULL;
	for (i = 0; i < teval->array.nr_keys; i++)
		eval->keys[i] = keys[i];
	eval->nr_keys = teval->array.nr_keys;
	teval->nr_evals++;

	ehash->next = teval->eval_hash[key];
	teval->eval_hash[key] = ehash;

	return ehash;
}

static struct eval_instance *
get_eval_instance(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_hash *ehash;
	int err = 0;
	int key = -1;

	ehash = find_eval(teval, keys, &err, &key);
	if (!ehash) {
		ehash = insert_eval(teval, keys, key);
		if (!ehash)
			return NULL;
	}
	return &ehash->eval;
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
	struct eval_hash *ehash;
	int err = 0;

	ehash = find_eval(teval, keys, &err, NULL);
	if (!ehash)
		return NULL;
	return ehash->eval.private;
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

static int create_results(struct traceeval *teval)
{
	struct eval_hash *ehash;
	int r = 0;
	int i;

	if (teval->results)
		return 0;

	teval->results = calloc(teval->nr_evals, sizeof(*teval->results));
	if (!teval->results)
		return -1;

	for (i = 0; i < HASH_SIZE; i++) {
		for (ehash = teval->eval_hash[i]; ehash; ehash = ehash->next) {
			teval->results[r++] = ehash->eval;
		}
	}
	return 0;
}

static int eval_sort(struct traceeval *teval, enum sort_type sort_type, bool ascending);

static struct eval_instance *get_result(struct traceeval *teval, size_t index)
{
	if (index >= teval->nr_evals)
		return NULL;

	if (!teval->results) {
		create_results(teval);
		if (!teval->results)
			return NULL;
		eval_sort(teval, KEYS, true);
	}

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
	struct eval_hash *ehash;
	int err = 0;

	ehash = find_eval(teval, keys, &err, NULL);
	if (!ehash)
		return -1;
	return ehash->eval.cnt;
}

ssize_t
traceeval_result_keys_total(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_hash *ehash;
	int err = 0;

	ehash = find_eval(teval, keys, &err, NULL);
	if (!ehash)
		return -1;
	return ehash->eval.total;
}

ssize_t
traceeval_result_keys_max(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_hash *ehash;
	int err = 0;

	ehash = find_eval(teval, keys, &err, NULL);
	if (!ehash)
		return -1;
	return ehash->eval.max;
}

ssize_t
traceeval_result_keys_min(struct traceeval *teval, struct traceeval_key *keys)
{
	struct eval_hash *ehash;
	int err = 0;

	ehash = find_eval(teval, keys, &err, NULL);
	if (!ehash)
		return -1;
	return ehash->eval.min;
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

static int cmp_evals(const void *A, const void *B, void *data)
{
	const struct eval_instance *a = A;
	const struct eval_instance *b = B;
	struct traceeval *teval = data;
	int err;

	return cmp_keys(&teval->array, a->keys, b->keys, &err);
}

static int cmp_evals_dec(const void *A, const void *B, void *data)
{
	struct traceeval *teval = data;
	int err;

	return cmp_keys(&teval->array, B, A, &err);
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
		if (ascending) {
			qsort_r(teval->results, teval->nr_evals,
				sizeof(*teval->results), cmp_evals, teval);
		} else {
			qsort_r(teval->results, teval->nr_evals,
				sizeof(*teval->results), cmp_evals_dec, teval);
		}
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
	return eval_sort(teval, KEYS, ascending);
}
