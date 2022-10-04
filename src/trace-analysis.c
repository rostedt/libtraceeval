// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#include <string.h>
#include <errno.h>
#include <traceeval.h>

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

struct traceeval_key_array *
traceeval_result_indx_key_array(struct traceeval *teval, size_t index)
{
	if (index >= teval->nr_evals)
		return NULL;
	return (struct traceeval_key_array *)&teval->evals[index];
}

ssize_t
traceeval_result_indx_cnt(struct traceeval *teval, size_t index)
{
	if (index >= teval->nr_evals)
		return -1;
	return teval->evals[index].cnt;
}

ssize_t
traceeval_result_indx_total(struct traceeval *teval, size_t index)
{
	if (index >= teval->nr_evals)
		return -1;
	return teval->evals[index].total;
}

ssize_t
traceeval_result_indx_max(struct traceeval *teval, size_t index)
{
	if (index >= teval->nr_evals)
		return -1;
	return teval->evals[index].max;
}

ssize_t
traceeval_result_indx_min(struct traceeval *teval, size_t index)
{
	if (index >= teval->nr_evals)
		return -1;
	return teval->evals[index].min;
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
