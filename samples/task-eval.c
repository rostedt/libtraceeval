#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <trace-cmd.h>
#include <traceeval.h>

static char *argv0;

static char *get_this_name(void)
{
	static char *this_name;
	char *arg;
	char *p;

	if (this_name)
		return this_name;

	arg = argv0;
	p = arg+strlen(arg);

	while (p >= arg && *p != '/')
		p--;
	p++;

	this_name = p;
	return p;
}

static void usage(void)
{
	char *p = get_this_name();

	printf("usage: %s [-c comm] trace.dat\n"
	       "\n"
	       "  Run this after running: trace-cmd record -e sched\n"
	       "\n"
	       "  Do some work and then hit Ctrl^C to stop the recording.\n"
	       "  Run this on the resulting trace.dat file\n"
	       "\n"
	       "-c comm - to look at only a specific process called 'comm'\n"
	       "\n",p);
	exit(-1);
}

static void __vdie(const char *fmt, va_list ap, int err)
{
	int ret = errno;
	char *p = get_this_name();

	if (err && errno)
		perror(p);
	else
		ret = -1;

	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);

	fprintf(stderr, "\n");
	exit(ret);
}

void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__vdie(fmt, ap, 0);
	va_end(ap);
}

void pdie(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__vdie(fmt, ap, 1);
	va_end(ap);
}

/* Used for stats */
#define DELTA_NAME		"delta"

static struct traceeval_type cpu_delta_keys[] = {
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "CPU",
	},
};

static struct traceeval_type cpu_delta_vals[] = {
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "Schedule state",
	},
};

static struct traceeval_type cpu_keys[] = {
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "CPU",
	},
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "Schedule state",
	},
};

static struct traceeval_type cpu_vals[] = {
	{
		.type = TRACEEVAL_TYPE_DELTA,
		.name = DELTA_NAME,
	},
};

static struct traceeval_type task_delta_keys[] = {
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "PID",
	},
};

static struct traceeval_type task_delta_vals[] = {
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "Schedule state"
	},
	{
		.type = TRACEEVAL_TYPE_STRING,
		.name = "COMM",
	},
};

static struct traceeval_type task_keys[] = {
	{
		.type = TRACEEVAL_TYPE_STRING,
		.name = "COMM"
	},
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "Schedule state"
	},
};

static struct traceeval_type task_vals[] = {
	{
		.type = TRACEEVAL_TYPE_POINTER,
		.name = "data",
	},
	{
		.type = TRACEEVAL_TYPE_DELTA,
		.name = DELTA_NAME,
	},
};

static struct traceeval_type thread_keys[] = {
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "TID",
	},
	{
		.type = TRACEEVAL_TYPE_NUMBER,
		.name = "Schedule state",
	},
};

static struct traceeval_type thread_vals[] = {
	{
		.type = TRACEEVAL_TYPE_DELTA,
		.name = DELTA_NAME,
	},
};

enum sched_state {
	RUNNING,
	BLOCKED,
	PREEMPT,
	SLEEP,
	IDLE,
	OTHER
};

struct process_data {
	struct traceeval	*teval_cpus;
	struct traceeval	*teval_threads;
};

struct task_data {
	struct traceeval	*teval_cpus;
	struct traceeval	*teval_tasks;
	unsigned long long	last_ts;
	char			*comm;
};

enum command {
	START,
	STOP
};

static void init_process_data(struct process_data *pdata)
{
	pdata->teval_cpus = traceeval_init(cpu_keys, cpu_vals);
	if (!pdata->teval_cpus)
		pdie("Creating trace eval cpus");

	pdata->teval_threads = traceeval_init(thread_keys, thread_vals);
	if (!pdata->teval_threads)
		pdie("Creating trace eval threads");
}

void set_process_data(struct task_data *tdata, const char *comm, void *data)
{
	struct traceeval_data keys[] = {
		DEFINE_TRACEEVAL_CSTRING(	comm	),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING	),
	};
	struct traceeval_data new_vals[2] = { };
	const struct traceeval_data *results;
	int ret;

	ret = traceeval_query(tdata->teval_tasks, keys, &results);
	if (ret > 0)
		goto out; /* It already exists ? */
	if (ret < 0)
		pdie("Could not query process data");

	TRACEEVAL_SET_POINTER(new_vals[0], data);
	TRACEEVAL_SET_DELTA(new_vals[1], 0, 0);

	ret = traceeval_insert(tdata->teval_tasks, keys, new_vals);
	if (ret < 0)
		pdie("Failed to set process data");

 out:
	traceeval_results_release(tdata->teval_tasks, results);
}

static struct process_data *alloc_pdata(struct task_data *tdata, const char *comm)
{
	struct process_data *pdata;

	pdata = calloc(1, sizeof(*pdata));
	if (!pdata)
		pdie("Allocating process data");
	init_process_data(pdata);
	set_process_data(tdata, comm, pdata);

	return pdata;
}

static struct process_data *
get_process_data(struct task_data *tdata, const char *comm)
{
	struct traceeval_data keys[] = {
		DEFINE_TRACEEVAL_CSTRING(	comm	),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING	),
	};
	const struct traceeval_data *results;
	void *data;
	int ret;

	ret = traceeval_query(tdata->teval_tasks, keys, &results);
	if (ret < 0)
		pdie("Could not query process data");
	if (ret == 0)
		return alloc_pdata(tdata, comm);

	data = results[0].pointer;
	traceeval_results_release(tdata->teval_tasks, results);
	return data;
}

static void update_cpu_data(struct task_data *tdata, int cpu, int state,
			    unsigned long long delta, unsigned long long ts)
{
	struct traceeval_data cpu_keys[2];
	struct traceeval_data vals[1];

	TRACEEVAL_SET_NUMBER(cpu_keys[0], cpu);
	TRACEEVAL_SET_NUMBER(cpu_keys[1], state);

	TRACEEVAL_SET_DELTA(vals[0], delta, ts);

	traceeval_insert(tdata->teval_cpus, cpu_keys, vals);
}

static void update_cpu_to_idle(struct task_data *tdata, struct tep_record *record)
{

	struct traceeval_data delta_keys[1];
	struct traceeval_data vals[1];
	const struct traceeval_data *results;
	unsigned long long delta;
	int ret;

	/* Finish previous run */
	TRACEEVAL_SET_NUMBER(delta_keys[0], record->cpu);

	ret = traceeval_delta_stop(tdata->teval_cpus, delta_keys, &results,
				   record->ts, &delta, NULL);

	if (ret > 0) {
		update_cpu_data(tdata, record->cpu, results[0].number,
				delta, record->ts);
		traceeval_results_release(tdata->teval_cpus, results);
	}

	/* Start the next state */
	TRACEEVAL_SET_NUMBER(vals[0], IDLE);
	traceeval_delta_start(tdata->teval_cpus, delta_keys, vals,
			      record->ts);
}

static void update_cpu_to_running(struct task_data *tdata, struct tep_record *record)
{
	struct traceeval_data delta_keys[1];
	struct traceeval_data cpu_keys[2];
	struct traceeval_data vals[1];
	const struct traceeval_data *results;
	unsigned long long delta;
	int ret;

	/* Initialize the delta and cpu keys to point to this CPU */
	TRACEEVAL_SET_NUMBER(delta_keys[0], record->cpu);
	TRACEEVAL_SET_NUMBER(cpu_keys[0], record->cpu);

	/* Test if the CPU was idle */
	ret = traceeval_delta_query(tdata->teval_cpus, delta_keys, &results);
	if (ret > 0 && results[0].number == IDLE) {
		/* Coming from idle */
		traceeval_delta_stop(tdata->teval_cpus, delta_keys, NULL,
				     record->ts, &delta, NULL);
		/* Update the idle teval */
		TRACEEVAL_SET_NUMBER(cpu_keys[1], IDLE);
		TRACEEVAL_SET_DELTA(vals[0], delta, record->ts);
		traceeval_insert(tdata->teval_cpus, cpu_keys, vals);
	}

	/* Continue with the CPU running */
	TRACEEVAL_SET_NUMBER(vals[0], RUNNING);
	traceeval_delta_continue(tdata->teval_cpus, delta_keys, vals,
				 record->ts);
}

static void update_thread(struct task_data *tdata, int pid, const char *comm,
			  enum sched_state state, unsigned long long delta,
			  unsigned long long ts)
{
		struct traceeval_data keys[2];
		struct traceeval_data pvals[2];
		struct traceeval_data vals[1];
		struct process_data *pdata;

		pdata = get_process_data(tdata, comm);

		TRACEEVAL_SET_NUMBER(keys[0], pid);
		TRACEEVAL_SET_NUMBER(keys[1], state);

		TRACEEVAL_SET_DELTA(vals[0], delta, ts);

		traceeval_insert(pdata->teval_threads, keys, vals);

		/* Also update the process */
		TRACEEVAL_SET_CSTRING(keys[0], comm);

		TRACEEVAL_SET_POINTER(pvals[0], pdata);
		TRACEEVAL_SET_DELTA(pvals[1], delta, ts);

		traceeval_insert(tdata->teval_tasks, keys, pvals);
}

static void start_running_thread(struct task_data *tdata,
				 struct tep_record *record,
				 const char *comm, int pid)
{
	const struct traceeval_data *results;
	struct traceeval_data delta_keys[1];
	struct traceeval_data vals[2];
	unsigned long long delta;
	unsigned long long val;
	int ret;

	TRACEEVAL_SET_NUMBER(delta_keys[0], pid);

	/* Find the previous stop state of this task */
	ret = traceeval_delta_stop(tdata->teval_tasks, delta_keys,
				   &results, record->ts, &delta, &val);
	if (ret > 0) {
		enum sched_state state = results[0].number;

		if (state == RUNNING)
			die("State %d is running! %lld -> %lld", pid, val, record->ts);
		update_thread(tdata, pid, comm, state, delta, record->ts);
		traceeval_results_release(tdata->teval_tasks, results);
	}

	TRACEEVAL_SET_NUMBER(vals[0], RUNNING);
	TRACEEVAL_SET_CSTRING(vals[1], comm);

	traceeval_delta_start(tdata->teval_tasks, delta_keys, vals, record->ts);
}

static int get_stop_state(unsigned long long val)
{
	if (val & 1)
		return SLEEP;
	if (val & 2)
		return BLOCKED;
	return PREEMPT;
}

static void sched_out(struct task_data *tdata, const char *comm,
		      struct tep_event *event,
		      struct tep_record *record, struct tep_format_field *prev_pid,
		      struct tep_format_field *prev_state)
{
	struct traceeval_data delta_keys[1];
	struct traceeval_data task_keys[2];
	struct traceeval_data task_vals[2];
	struct traceeval_data vals[1];
	struct process_data *pdata;
	const struct traceeval_data *results;
	unsigned long long delta;
	unsigned long long val;
	int state;
	int old_state;
	int pid;
	int ret;

	ret = tep_read_number_field(prev_pid, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch prev_pid for record");
	pid = val;

	/* Idle is handled by sched_in() */
	if (!pid)
		return;

	ret = tep_read_number_field(prev_state, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_pid for record");
	state = get_stop_state(val);

	TRACEEVAL_SET_NUMBER(delta_keys[0], pid);

	ret = traceeval_delta_stop(tdata->teval_tasks, delta_keys, &results,
				   record->ts, &delta, &val);

	TRACEEVAL_SET_NUMBER(task_vals[0], state);
	TRACEEVAL_SET_CSTRING(task_vals[1], comm);

	if (ret > 0)
		old_state = results[0].number;

	/* Start recording why this task is off the CPU */
	traceeval_delta_start(tdata->teval_tasks, delta_keys, task_vals, record->ts);
	if (ret <= 0)
		return;

	if (old_state != RUNNING)
		die("Not running %d from %lld to %lld",
		    old_state, val, record->ts);

	TRACEEVAL_SET_CSTRING(task_keys[0], comm);
	TRACEEVAL_SET_NUMBER(task_keys[1], RUNNING);

	pdata = get_process_data(tdata, comm);

	TRACEEVAL_SET_POINTER(task_vals[0], pdata);
	TRACEEVAL_SET_DELTA(task_vals[1], delta, record->ts);

	traceeval_insert(tdata->teval_tasks, task_keys, task_vals);

	TRACEEVAL_SET_NUMBER(task_keys[0], pid);

	TRACEEVAL_SET_DELTA(vals[0], delta, record->ts);

	traceeval_insert(pdata->teval_threads, task_keys, vals);

	TRACEEVAL_SET_NUMBER(task_keys[0], record->cpu);

	traceeval_insert(pdata->teval_cpus, task_keys, vals);
}

static void sched_in(struct task_data *tdata, const char *comm,
		     struct tep_event *event,
		     struct tep_record *record, struct tep_format_field *next_pid)
{
	unsigned long long val;
	int ret;
	int pid;

	ret = tep_read_number_field(next_pid, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_pid for record");
	pid = val;

	/* Idle task */
	if (!pid) {
		update_cpu_to_idle(tdata, record);
		return;
	}

	/* Continue measuring CPU running time */
	update_cpu_to_running(tdata, record);
	start_running_thread(tdata, record, comm, pid);
}

static struct tep_format_field *get_field(struct tep_event *event, const char *name)
{
	static struct tep_format_field *field;

	field = tep_find_field(event, name);
	if (!field)
		die("Could not find field %s for %s",
		    name, event->name);

	return field;
}

static int switch_func(struct tracecmd_input *handle, struct tep_event *event,
		       struct tep_record *record, int cpu, void *data)
{
	static struct tep_format_field *prev_comm;
	static struct tep_format_field *prev_pid;
	static struct tep_format_field *prev_state;
	static struct tep_format_field *next_comm;
	static struct tep_format_field *next_pid;
	struct task_data *tdata = data;
	const char *comm;

	if (!next_comm) {
		prev_comm = get_field(event, "prev_comm");
		prev_pid = get_field(event, "prev_pid");
		prev_state = get_field(event, "prev_state");

		next_comm = get_field(event, "next_comm");
		next_pid = get_field(event, "next_pid");
	}

	comm = record->data + prev_comm->offset;
	if (!tdata->comm || strcmp(comm, tdata->comm) == 0)
		sched_out(tdata, comm, event, record, prev_pid, prev_state);

	comm = record->data + next_comm->offset;
	if (!tdata->comm || strcmp(comm, tdata->comm) == 0)
		sched_in(tdata, comm, event, record, next_pid);

	return 0;
}

static void print_microseconds(int idx, unsigned long long nsecs)
{
	unsigned long long usecs;

	usecs = nsecs / 1000;
	if (!nsecs || usecs)
		printf("%*lld\n", idx, usecs);
	else
		printf("%*d.%03lld\n", idx, 0, nsecs);
}

/*
 * Sort all the processes by the RUNNING state.
 *  If A and B have the same COMM, then sort by state.
 *  else
 *    Find the RUNNNIG state for A and B
 *    If the RUNNING state does not exist, it's considered -1
 *  If RUNNING is equal, then sort by COMM.
 */
static int compare_pdata(struct traceeval *teval,
				const struct traceeval_data *Akeys,
				const struct traceeval_data *Avals,
				const struct traceeval_data *Bkeys,
				const struct traceeval_data *Bvals,
				void *data)
{
	struct traceeval_data keysA[] = {
		DEFINE_TRACEEVAL_CSTRING(	Akeys[0].cstring	),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING			), };
	struct traceeval_data keysB[] = {
		DEFINE_TRACEEVAL_CSTRING(	Bkeys[0].cstring	),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING			), };
	struct traceeval_stat *statA;
	struct traceeval_stat *statB;
	unsigned long long totalA = -1;
	unsigned long long totalB = -1;

	/* First check if we are on the same task */
	if (strcmp(Akeys[0].cstring, Bkeys[0].cstring) == 0) {
		/* Sort decending */
		if (Bkeys[1].number > Akeys[1].number)
			return -1;
		return Bkeys[1].number != Akeys[1].number;
	}

	/* Get the RUNNING values for both processes */
	statA = traceeval_stat(teval, keysA, DELTA_NAME);
	if (statA)
		totalA = traceeval_stat_total(statA);

	statB = traceeval_stat(teval, keysB, DELTA_NAME);
	if (statB)
		totalB = traceeval_stat_total(statB);

	if (totalB < totalA)
		return -1;
	if (totalB > totalA)
		return 1;

	return strcmp(Bkeys[0].cstring, Akeys[0].cstring);
}

static void display_cpus(struct traceeval *teval)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(teval);
	const struct traceeval_data *keys;
	struct traceeval_stat *stat;
	int last_cpu = -1;

	if (!iter)
		pdie("Could not get iterator?");

	printf("\n");

	traceeval_iterator_sort(iter, cpu_keys[0].name, 0, true);
	traceeval_iterator_sort(iter, cpu_keys[1].name, 1, true);

	while (traceeval_iterator_next(iter, &keys) > 0) {
		int state = keys[1].number;
		int cpu = keys[0].number;

		stat = traceeval_iterator_stat(iter, DELTA_NAME);
		if (!stat)
			continue; // die?

		if (last_cpu != cpu)
			printf("    CPU [%d]:\n", cpu);

		switch (state) {
		case RUNNING:
			printf("       Running: ");
			break;
		case IDLE:
			printf("          Idle: ");
			break;
		case BLOCKED:
		case PREEMPT:
		case SLEEP:
		case OTHER:
			printf("         \?\?(%d): ", state);
			break;
		}
		printf(" time (us):");
		print_microseconds(12, traceeval_stat_total(stat));

		last_cpu = cpu;
	}

	if (last_cpu < 0)
		die("No result for CPUs\n");
}

static void display_state_times(int state, unsigned long long total)
{
	switch (state) {
	case RUNNING:
		printf("      Total run time (us):");
		print_microseconds(14, total);
		break;
	case BLOCKED:
		printf("      Total blocked time (us):");
		print_microseconds(10, total);
		break;
	case PREEMPT:
		printf("      Total preempt time (us):");
		print_microseconds(10, total);
		break;
	case SLEEP:
		printf("      Total sleep time (us):");
		print_microseconds(12, total);
	}
}

static void display_threads(struct traceeval *teval)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(teval);
	const struct traceeval_data *keys;
	struct traceeval_stat *stat;
	int last_tid = -1;

	traceeval_iterator_sort(iter, thread_keys[0].name, 0, true);
	traceeval_iterator_sort(iter, thread_keys[1].name, 1, true);

	while (traceeval_iterator_next(iter, &keys) > 0) {
		int state = keys[1].number;
		int tid = keys[0].number;

		stat = traceeval_iterator_stat(iter, DELTA_NAME);
		if (!stat)
			continue; // die?

		if (last_tid != keys[0].number)
			printf("\n    thread id: %d\n", tid);

		last_tid = tid;

		display_state_times(state, traceeval_stat_total(stat));
	}

	if (last_tid < 0)
		die("No result for threads\n");
}

static void display_process(struct process_data *pdata)
{
	display_threads(pdata->teval_threads);
	display_cpus(pdata->teval_cpus);
	printf("\n");
}

static void display_process_stats(struct traceeval *teval,
				  struct process_data *pdata, const char *comm)
{
	struct traceeval_stat *stat;
	unsigned long long delta;
	struct traceeval_data keys[] = {
		DEFINE_TRACEEVAL_CSTRING(	comm		),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING		),
	};

	for (int i = 0; i < OTHER; i++) {
		TRACEEVAL_SET_NUMBER(keys[1], i);

		delta = 0;
		stat = traceeval_stat(teval, keys, DELTA_NAME);
		if (stat)
			delta = traceeval_stat_total(stat);
		display_state_times(i, delta);
	}
}

static void display_processes(struct traceeval *teval)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(teval);
	const struct traceeval_data *keys;
	const char *last_comm = "";
	int ret;

	traceeval_iterator_sort_custom(iter, compare_pdata, NULL);

	while (traceeval_iterator_next(iter, &keys) > 0) {
		const struct traceeval_data *results;
		struct process_data *pdata = NULL;
		const char *comm = keys[0].cstring;

		if (strcmp(comm, last_comm) == 0)
			continue;

		last_comm = comm;

		ret = traceeval_iterator_query(iter, &results);
		if (ret < 0)
			pdie("Could not query iterator");
		if (ret < 1)
			continue; /* ?? */

		pdata = results[0].pointer;
		traceeval_results_release(teval, results);

		printf("Task: %s\n", comm);

		display_process_stats(teval, pdata, comm);
		if (pdata)
			display_process(pdata);
	}
}

static void display(struct task_data *tdata)
{
	struct traceeval *teval = tdata->teval_cpus;
	struct traceeval_iterator *iter = traceeval_iterator_get(teval);
	const struct traceeval_data *keys;
	struct traceeval_stat *stat;
	unsigned long long total_time = 0;
	unsigned long long idle_time = 0;

	if (tdata->comm) {
		return display_processes(tdata->teval_tasks);
	}

	printf("Total:\n");

	if (!iter)
		pdie("No cpus?");

	while (traceeval_iterator_next(iter, &keys) > 0) {
		int state = keys[1].number;

		stat = traceeval_iterator_stat(iter, DELTA_NAME);
		if (!stat)
			continue;

		switch (state) {
		case RUNNING:
			total_time += traceeval_stat_total(stat);
			break;
		case IDLE:
			idle_time += traceeval_stat_total(stat);
			break;
		default:
			die("Invalid CPU state: %d\n", state);
		}
	}

	printf("  Total  run time (us):");
	print_microseconds(16, total_time);
	printf("  Total idle time (us):");
	print_microseconds(16, idle_time);

	display_cpus(tdata->teval_cpus);

	printf("\n");
	display_processes(tdata->teval_tasks);
}

static void free_tdata(struct task_data *tdata)
{
}

static void finish_leftovers(struct task_data *data)
{
	const struct traceeval_data *results;
	const struct traceeval_data *keys;
	struct traceeval_iterator *iter;
	unsigned long long delta;
	enum sched_state state;
	const char *comm;
	int pid;

	iter = traceeval_iterator_delta_start_get(data->teval_tasks);
	while (traceeval_iterator_next(iter, &keys) > 0) {
		traceeval_iterator_delta_stop(iter, &results, data->last_ts,
					      &delta, NULL);

		pid = keys[0].number;

		state = results[0].number;
		comm = results[1].cstring;

		update_thread(data, pid, comm, state, delta, data->last_ts);
	}
	traceeval_iterator_put(iter);

	iter = traceeval_iterator_delta_start_get(data->teval_cpus);
	while (traceeval_iterator_next(iter, &keys) > 0) {
		traceeval_iterator_delta_stop(iter, &results, data->last_ts,
					      &delta, NULL);
		update_cpu_data(data, keys[0].number, results[0].number,
				delta, data->last_ts);
	}
	traceeval_iterator_put(iter);

}

static int event_callback(struct tracecmd_input *handle,
			  struct tep_record *record, int cpu, void *d)
{
	struct task_data *data = d;

	data->last_ts = record->ts;
	return 0;
}

int main (int argc, char **argv)
{
	struct tracecmd_input *handle;
	struct task_data data;
	int c;

	memset(&data, 0, sizeof(data));

	argv0 = argv[0];

	while ((c = getopt(argc, argv, "c:h")) >= 0) {
		switch (c) {
		case 'c':
			data.comm = optarg;
			break;
		case 'h':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	handle = tracecmd_open(argv[0], TRACECMD_FL_LOAD_NO_PLUGINS);
	if (!handle)
		pdie("Error opening %s", argv[0]);

	data.teval_tasks = traceeval_init(task_keys, task_vals);
	if (!data.teval_tasks)
		pdie("Creating trace eval processe data");

	if (traceeval_delta_create(data.teval_tasks, task_delta_keys,
				   task_delta_vals) < 0)
		pdie("Creating trace delta threads");

	data.teval_cpus = traceeval_init(cpu_keys, cpu_vals);
	if (!data.teval_cpus)
		pdie("Creating trace eval");

	if (traceeval_delta_create(data.teval_cpus, cpu_delta_keys, cpu_delta_vals) < 0)
		pdie("Creating trace delta cpus");

	tracecmd_follow_event(handle, "sched", "sched_switch", switch_func, &data);

	tracecmd_iterate_events(handle, NULL, 0, event_callback, &data);

	finish_leftovers(&data);

	display(&data);

	free_tdata(&data);

	return 0;
}
