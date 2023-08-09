/* SPDX-License-Identifier: MIT */
/*
 * libtraceeval interface for unit testing.
 *
 * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 * Copyright (C) 2023 Google Inc, Stevie Alvarez <stevie.6strings@gmail.com>
 */

#ifndef __LIBTRACEEVAL_TEST_H__
#define __LIBTRACEEVAL_TEST_H__

#include <traceeval-hist.h>

int traceeval_compare(struct traceeval *orig, struct traceeval *copy);

#endif /* __LIBTRACEEVAL_TEST_H__ */
