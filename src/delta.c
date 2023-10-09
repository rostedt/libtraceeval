/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */

#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include <traceeval.h>
#include "eval-local.h"

struct traceeval_delta {
	struct traceeval		*teval;
};

#define TEVAL_TIMESTAMP_IDX(teval)         ((teval)->nr_val_types - 1)

/* Get to the saved timestamp value */
#define TEVAL_TIMESTAMP(teval, val)                (val)[TEVAL_TIMESTAMP_IDX(teval)].number_64

#define TEVAL_TIMESTAMP_NAME	"__TRACEEVAL_DELTA_TIMESTAMP__"

/**
 * traceeval_delta_create_data_size - create a delta for a teval
 * @teval: The traceeval to create a delta query for
 * @keys: Defines the keys to differentiate traceeval delta entries
 * @vals: Defines values attached to entries differentiated by @keys.
 * @nr_keys: The number of @keys passed in
 * @nr_vals: The number of @vals passed in
 * @sizeof_type: The size of struct traceeval_type
 * @sizeof_data: The size of struct traceeval_data
 *
 * This adds a specialized internal traceeval descriptor to @teval.
 * This descriptor is used to find the start and stop timings between
 * two events. The @keys are used to map the start and stop events.
 * The @keys should be something that is in both events to tell that
 * they are related. Note the @keys here are not related to the keys
 * that created the traceeval in traceeval_init().
 *
 * The @vals is used to store information from the start event that can
 * then be used at the stop event and returned in the traceeval_delta_stop().
 *
 * Returns 0 on success and -1 on error.
 */
int traceeval_delta_create_data_size(struct traceeval *teval,
				     struct traceeval_type *keys,
				     struct traceeval_type *vals,
				     size_t nr_keys,
				     size_t nr_vals,
				     size_t sizeof_type,
				     size_t sizeof_data)
{
	struct traceeval_type *delta_vals;
	struct traceeval_type *val;
	struct traceeval_delta *tdelta;
	int i;

	/* Only one can exist */
	if (teval->tdelta)
		return -1;

	tdelta = calloc(1, sizeof(*tdelta));
	if (!tdelta)
		return -1;

	if (vals) {
		for (i = 0; i < nr_vals && vals[i].type != TRACEEVAL_TYPE_NONE; i++)
			;
		nr_vals = i;
	} else {
		nr_vals = 0;
	}

	/* Copy the vals and add the save timestamp at the end */
	delta_vals = calloc(nr_vals + 1, sizeof(*delta_vals));
	if (!delta_vals)
		goto fail;

	for (i = 0; i < nr_vals; i++)
		delta_vals[i] = vals[i];

	/* Append the delta value */
	val = &delta_vals[nr_vals++];
	val->name = TEVAL_TIMESTAMP_NAME;
	val->type = TRACEEVAL_TYPE_NUMBER_64;

	tdelta->teval = traceeval_init_data_size(keys, delta_vals, nr_keys,
						 nr_vals, sizeof_type,
						 sizeof_data);
	/* The delta_vals are no longer needed */
	free(delta_vals);

	if (!tdelta->teval)
		goto fail;

	tdelta->teval->flags |= TEVAL_FL_DELTA;

	teval->tdelta = tdelta;

	return 0;
 fail:
	free(tdelta);
	return -1;
}

/*
 * __delta_release - release the resources of a traceeval_delta
 * @tdelta: The traceeval_delta descriptor to release
 *
 * Frees all the resources created by traceeval_delta_create().
 */
__hidden void __delta_release(struct traceeval_delta *tdelta)
{
	if (!tdelta)
		return;

	traceeval_release(tdelta->teval);
	free(tdelta);
}

/**
 * traceeval_delta_remove - Remove an instance from a traceeval_delta
 * @teval: The traceeval descriptor
 * @keys: The keys to find the matching element to remove
 * @nr_keys: The number of @keys
 *
 * Returns 1 if it found and removed an item,
 *         0 if it did not find an time matching @keys
 *        -1 if there was an error.
 */
int traceeval_delta_remove_size(struct traceeval *teval,
				const struct traceeval_data *keys,
				size_t nr_keys)
{
	if (!teval->tdelta)
		return -1;
	return traceeval_remove_size(teval->tdelta->teval, keys, nr_keys);
}

/*
 * traceeval_delta_query - find the last instance defined by the keys
 * @teval: The traceeval descriptor to search the traceeval_delta from
 * @keys: A list of data to look for
 * @results: A pointer to where to place the results (if found)
 *
 * This does a lookup for an instance within the traceeval_delta.
 * The @keys is an array defined by the keys declared in traceeval_delta_init().
 * The @keys will return an item that had the same keys when it was
 * inserted by traceeval_delta_start().
 *
 * The @results will hold the vals passed to the last traceeval_delta_start()
 * for the given @keys if found, or undefined if not.
 *
 * Note, when the caller is done with @results, it must call
 * traceeval_results_release() on it.
 *
 * Returns 1 if found, 0 if not found, and -1 on error.
 */
int traceeval_delta_query_size(struct traceeval *teval,
			       const struct traceeval_data *keys,
			       size_t nr_keys, const struct traceeval_data **results)
{
	if (!teval->tdelta)
		return -1;
	return traceeval_query_size(teval->tdelta->teval, keys,
				    nr_keys, results);
}

static int delta_start(struct traceeval *teval,
		       const struct traceeval_data *keys, size_t nr_keys,
		       const struct traceeval_data *vals, size_t nr_vals,
		       unsigned long long timestamp, bool cont)
{
	struct entry *entry;
	int ret;
	int i;

	if (!teval->tdelta)
		return -1;

	teval = teval->tdelta->teval;

	if (nr_keys != teval->nr_key_types ||
	    nr_vals != teval->nr_val_types - 1)
		return -1;

	ret = _teval_get_entry(teval, keys, &entry);
	if (ret < 0)
		return ret;

	if (ret) {
		if (cont && TEVAL_TIMESTAMP(teval, entry->vals))
			return 0;

		for (i = 0; i < nr_vals; i++)
			entry->vals[i] = vals[i];

		TRACEEVAL_SET_NUMBER_64(entry->vals[i], timestamp);

		return 0;
	} else {
		struct traceeval_data new_vals[teval->nr_val_types] = {};

		for (i = 0; i < nr_vals; i++)
			new_vals[i] = vals[i];

		TRACEEVAL_SET_NUMBER_64(new_vals[i], timestamp);

		return _teval_insert(teval, keys, teval->nr_key_types,
				     new_vals, teval->nr_val_types);
	}
}

/*
 * traceeval_delta_start - start the timings of a traceeval_delta
 * @teval: The traceeval descriptor
 * @keys: The keys of the instance to start the timing for
 * @nr_keys: The number of @keys
 * @vals: Values to save to pass to traceeval_delta_stop()
 * @nr_vals: The number of @vals
 * @timestamp: The timestamp for the start of this instance
 *
 * The traceeval_delta is used to add start and stop times for the objects
 * in the traceeval. This function denotes that the instance represented by
 * @keys is in the process of "starting". The @timestamp is the start time.
 * This should be matched by a corresponding traceeval_delta_stop().
 *
 * The @vals will be saved for the matching @keys and returned in the
 * results of a traceeval_delta_stop().
 *
 * Returns 0 on succes and -1 on error.
 */
int traceeval_delta_start_size(struct traceeval *teval,
			       const struct traceeval_data *keys, size_t nr_keys,
			       const struct traceeval_data *vals, size_t nr_vals,
			       unsigned long long timestamp)
{
	return delta_start(teval, keys, nr_keys, vals, nr_vals,
			   timestamp, false);
}

/*
 * traceeval_delta_continue - continue the timings of a traceeval_delta
 * @teval: The traceeval descriptor
 * @keys: The keys of the instance to continue the timing for
 * @nr_keys: The number of @keys
 * @vals: Values to save to pass to traceeval_delta_stop()
 * @nr_vals: The number of @vals
 * @timestamp: The timestamp for the start of this instance
 *
 * This acts similar to traceeval_delta_start() except that if this is called
 * between a traceeval_delta_start() and a traceeval_delta_stop(), it will
 * not doing anything. There's times that multiple starts may happen, and only
 * the first one should be used. In that case, traceeval_delta_continue() will
 * update the timings on the first run, and will not do any update until
 * a traceeval_delta_stop() is executed on the given @keys.
 *
 * Note that even the @vals are ignored if this is called between the
 * traceeval_delta_start/continue() and a traceeval_delta_stop().
 *
 * Returns 0 on succes and -1 on error.
 */
int traceeval_delta_continue_size(struct traceeval *teval,
				  const struct traceeval_data *keys, size_t nr_keys,
				  const struct traceeval_data *vals, size_t nr_vals,
				  unsigned long long timestamp)
{
	return delta_start(teval, keys, nr_keys, vals, nr_vals, timestamp, true);
}

/*
 * traceeval_delta_stop - stop the timings of a traceeval_delta
 * @teval: The traceeval descriptor
 * @keys: The keys of the instance to stop the timing for
 * @nr_keys: The number of @keys
 * @results: A pointer to place the passed in vals of start (or NULL)
 * @timestamp: The timestamp for the stop of this instance
 * @delta: Retruns the calculated delta from the previous timestamp
 * @stop_ts: Returns the timestamp of the matching start
 *
 * The traceeval_delta is used to add start and stop times for the objects
 * in the traceeval. This function denotes that the instance represented by
 * @keys is in the process of "stopping". The @timestamp is the stop time.
 * This function does not do anything if there was no matching
 * traceeval_delta_start() or traceeval_delta_continue() for the given @keys.
 * If there is a match, then it will take the @timestamp and subtract it
 * from the saved timestamp of the traceeval_delta_start/continue(),
 * and record the resulting delta with the given traceeval_stat information.
 *
 * If @results is not NULL then it will be assigned to the vals passed to
 * traceeval_delta_start/continue().
 *
 * If @start_ts is not NULL, then it will get assigned to the timestamp
 * passed to the matching tarceeval_delta_start/continue().
 *
 * Returns 1 if updated, 0 if not found, and -1 on error.
 */
int traceeval_delta_stop_size(struct traceeval *teval,
			      const struct traceeval_data *keys, size_t nr_keys,
			      const struct traceeval_data **results,
			      unsigned long long timestamp,
			      unsigned long long *delta,
			      unsigned long long *start_ts)

{
	unsigned long long ts;
	struct entry *entry;
	int ret;

	if (!teval->tdelta)
		return -1;

	teval = teval->tdelta->teval;

	ret = _teval_get_entry(teval, keys, &entry);
	if (ret <= 0)
		return ret;

	ts = TEVAL_TIMESTAMP(teval, entry->vals);
	if (!ts)
		return 0;

	if (results)
		*results = entry->vals;

	if (delta)
		*delta = timestamp - ts;

	if (start_ts)
		*start_ts = ts;

	/* Clear the saved timestamp to allow continue to work again */
	TEVAL_TIMESTAMP(teval, entry->vals) = 0;

	return 1;
}

static int create_delta_iter_array(struct traceeval_iterator *iter)
{
	struct traceeval *teval = iter->teval;
	struct hash_table *hist = teval->hist;
	struct hash_iter *hiter;
	struct hash_item *item;
	size_t ts_idx = teval->nr_val_types - 1;
	size_t idx = 0;
	int i;

	iter->nr_entries = hash_nr_items(hist);
	iter->entries = calloc(iter->nr_entries, sizeof(*iter->entries));
	if (!iter->entries)
		return -1;

	for (i = 0, hiter = hash_iter_start(hist); (item = hash_iter_next(hiter)); i++) {
		struct entry *entry = container_of(item, struct entry, hash);

		/* Only add entries where the timestamp is non zero */
		if (!entry->vals[ts_idx].number_64)
			continue;

		iter->entries[idx++] = entry;
	}

	iter->nr_entries = idx;

	/* No sorting for this */
	iter->no_sort = true;

	return 0;
}

/**
 * traceeval_iterator_delta_start_get - return iterator on delta start
 * @teval: traceeval to get the delta iterator from
 *
 * This is used to find any element of a traceeval_delta that had
 * a traceeval_delta_start() or traceeval_delta_continue() called on
 * it without a traceeval_delta_stop(). That is, any "hanging" elements.
 */
struct traceeval_iterator *traceeval_iterator_delta_start_get(struct traceeval *teval)
{
	struct traceeval_iterator *iter;
	int ret;

	if (!teval->tdelta)
		return NULL;

	iter = calloc(1, sizeof(*iter));
	if (!iter)
		return NULL;

	iter->teval = teval->tdelta->teval;

	ret = create_delta_iter_array(iter);

	if (ret < 0) {
		free(iter);
		iter = NULL;
	}

	return iter;
}

int traceeval_iterator_delta_stop(struct traceeval_iterator *iter,
				  const struct traceeval_data **results,
				  unsigned long long timestamp,
				  unsigned long long *delta,
				  unsigned long long *start_ts)
{
	unsigned long long ts;
	struct entry *entry;

	if (iter->next < 1 || iter->next > iter->nr_entries)
		return -1;

	entry = iter->entries[iter->next - 1];

	if (results)
		*results = entry->vals;

	ts = entry->vals[iter->teval->nr_val_types - 1].number_64;

	if (delta)
		*delta = timestamp - ts;

	if (start_ts)
		*start_ts = ts;

	return 1;
}
