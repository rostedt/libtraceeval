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
	char			*comm;
	int			state;
};

struct task_data {
	struct traceeval	*teval_cpus;
	struct traceeval	*teval_processes;
	char			*comm;
};

enum command {
	START,
	STOP
};

static void update_process(struct task_data *tdata, const char *comm,
			   enum sched_state state, enum command cmd,
			   unsigned long long ts)
{
	struct traceeval_key keys[] = {
		{
			.type = TRACEEVAL_TYPE_STRING,
			.string = comm,
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.number = state,
		}
	};
	int ret;

	switch (cmd) {
	case START:
		ret = traceeval_n_start(tdata->teval_processes, keys, ts);
		if (ret < 0)
			pdie("Could not start process");
		return;
	case STOP:
		ret = traceeval_n_stop(tdata->teval_processes, keys, ts);
		if (ret < 0)
			pdie("Could not stop process");
		return;
	}
}

static void start_process(struct task_data *tdata, const char *comm,
			   enum sched_state state, unsigned long long ts)
{
	update_process(tdata, comm, state, START, ts);
}

static void stop_process(struct task_data *tdata, const char *comm,
			   enum sched_state state, unsigned long long ts)
{
	update_process(tdata, comm, state, STOP, ts);
}

static struct process_data *
get_process_data(struct task_data *tdata, const char *comm)
{
	struct traceeval_key keys[] = {
		{
			.type = TRACEEVAL_TYPE_STRING,
			.string = comm,
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.number = RUNNING,
		}
	};

	return traceeval_n_get_private(tdata->teval_processes, keys);
}

void set_process_data(struct task_data *tdata, const char *comm, void *data)
{
	struct traceeval_key keys[] = {
		{
			.type = TRACEEVAL_TYPE_STRING,
			.string = comm,
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.number = RUNNING,
		}
	};
	int ret;

	ret = traceeval_n_set_private(tdata->teval_processes, keys, data);
	if (ret < 0)
		pdie("Failed to set process data");
}

static void update_cpu(struct traceeval *teval, int cpu,
		       enum sched_state state, enum command cmd,
		       unsigned long long ts)
{
	struct traceeval_key keys[] = {
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.number = cpu,
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.number = state,
		}
	};
	int ret;

	switch (cmd) {
	case START:
		ret = traceeval_n_continue(teval, keys, ts);
		if (ret < 0)
			pdie("Could not start CPU");
		return;
	case STOP:
		ret = traceeval_n_stop(teval, keys, ts);
		if (ret < 0)
			pdie("Could not stop CPU");
		return;
	}
}

static void start_cpu(struct traceeval *teval, int cpu,
		      enum sched_state state,  unsigned long long ts)
{
	update_cpu(teval, cpu, state, START, ts);
}

static void stop_cpu(struct traceeval *teval, int cpu,
		     enum sched_state state, unsigned long long ts)
{
	update_cpu(teval, cpu, state, STOP, ts);
}

static void update_thread(struct process_data *pdata, int tid,
			  enum sched_state state, enum command cmd,
			  unsigned long long ts)
{
	struct traceeval_key keys[] = {
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.number = tid,
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.number = state,
		}
	};
	int ret;

	switch (cmd) {
	case START:
		ret = traceeval_n_start(pdata->teval_threads, keys, ts);
		if (ret < 0)
			pdie("Could not start thread");
		return;
	case STOP:
		ret = traceeval_n_stop(pdata->teval_threads, keys, ts);
		if (ret < 0)
			pdie("Could not stop thread");
		return;
	}
}

static void start_thread(struct process_data *pdata, int tid,
			   enum sched_state state, unsigned long long ts)
{
	update_thread(pdata, tid, state, START, ts);
}

static void stop_thread(struct process_data *pdata, int tid,
			enum sched_state state, unsigned long long ts)
{
	update_thread(pdata, tid, state, STOP, ts);
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

static void init_process_data(struct process_data *pdata)
{
	struct traceeval_key_info cpu_info[] = {
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.name = "CPU",
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.name = "Schedule state",
		}
	};
	struct traceeval_key_info thread_info[] = {
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.name = "TID",
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.name = "Schedule state",
		}
	};

	pdata->teval_cpus = traceeval_2_alloc("CPUs", cpu_info);
	if (!pdata->teval_cpus)
		pdie("Creating trace eval");

	pdata->teval_threads = traceeval_2_alloc("Threads", thread_info);
	if (!pdata->teval_threads)
		pdie("Creating trace eval");
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

static void sched_out(struct task_data *tdata, const char *comm,
		      struct tep_event *event,
		      struct tep_record *record, struct tep_format_field *prev_pid,
		      struct tep_format_field *prev_state)
{
	struct process_data *pdata;
	unsigned long long val;
	int pid;
	int ret;

	ret = tep_read_number_field(prev_pid, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_pid for record");

	/* Ignore the idle task */
	pid = val;
	if (!pid) {
		/* Record the runtime for the process CPUs */
		stop_cpu(tdata->teval_cpus, record->cpu, IDLE, record->ts);
		return;
	}

	/* The process is scheduling out. Stop the run time. */
	update_process(tdata, comm, RUNNING, STOP, record->ts);

	/* Get the process data from the process running state */
	pdata = get_process_data(tdata, comm);
	if (!pdata)
		pdata = alloc_pdata(tdata, comm);

	ret = tep_read_number_field(prev_state, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_pid for record");
	val &= 3;
	/*
	 * Save the state the process is exiting with. Will need this
	 * when scheduled back in.
	 */
	if (!val)
		pdata->state = PREEMPT;
	else if (val & 1)
		pdata->state = SLEEP;
	else if (val & 2)
		pdata->state = BLOCKED;

	/* Record the state timings for the process */
	start_process(tdata, comm, pdata->state, record->ts);

	/* Record the state timings for the individual thread */
	stop_thread(pdata, pid, RUNNING, record->ts);

	/* Record the state timings for the individual thread */
	start_thread(pdata, pid, pdata->state, record->ts);

	/* Record the runtime for the process CPUs */
	stop_cpu(pdata->teval_cpus, record->cpu, RUNNING, record->ts);

	/* Record the runtime for the all CPUs */
	stop_cpu(tdata->teval_cpus, record->cpu, RUNNING, record->ts);
}

static void sched_in(struct task_data *tdata, const char *comm,
		     struct tep_event *event,
		     struct tep_record *record, struct tep_format_field *next_pid)
{
	struct process_data *pdata;
	unsigned long long val;
	bool is_new = false;
	int ret;
	int pid;

	ret = tep_read_number_field(next_pid, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_pid for record");
	pid = val;

	/* Ignore the idle task */
	if (!pid) {
		/* Record the runtime for the process CPUs */
		start_cpu(tdata->teval_cpus, record->cpu, IDLE, record->ts);
		return;
	}

	/* Start recording the running time of this process */
	start_process(tdata, comm, RUNNING, record->ts);

	pdata = get_process_data(tdata, comm);

	/* Start recording the running time of process CPUs */
	start_cpu(tdata->teval_cpus, record->cpu, RUNNING, record->ts);

	/* If there was no pdata, then this process did not go through sched out */
	if (!pdata) {
		pdata = alloc_pdata(tdata, comm);
		is_new = true;
	}

	/* Record the state timings for the individual thread */
	start_thread(pdata, pid, RUNNING, record->ts);

	/* Start recording the running time of process CPUs */
	start_cpu(pdata->teval_cpus, record->cpu, RUNNING, record->ts);

	/* If it was just created, there's nothing to stop */
	if (is_new)
		return;

	/* Stop recording the thread time for its scheduled out state */
	stop_thread(pdata, val, pdata->state, record->ts);

	/* Stop recording the process time for its scheduled out state */
	stop_process(tdata, comm, pdata->state, record->ts);
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

static void display_cpus(struct traceeval *teval)
{
	struct traceeval_key_array *karray;
	const struct traceeval_key *ckey;
	const struct traceeval_key *skey;
	int last_cpu = -1;
	int i, nr;

	printf("\n");

	nr = traceeval_result_nr(teval);
	if (!nr)
		die("No result for CPUs\n");

	for (i = 0; i < nr; i++) {
		karray = traceeval_result_indx_key_array(teval, i);
		if (!karray)
			die("No cpu key for result %d\n", i);
		ckey = traceeval_key_array_indx(karray, 0);
		skey = traceeval_key_array_indx(karray, 1);


		if (last_cpu != ckey->number)
			printf("    CPU [%d]:\n", (int)ckey->number);

		switch (skey->number) {
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
			printf("         \?\?(%ld): ", skey->number);
			break;
		}
		printf(" time (us):");
		print_microseconds(12, traceeval_result_indx_total(teval, i));

		last_cpu = ckey->number;
	}
}

static void display_thread(struct traceeval *teval, int tid)
{
	struct traceeval_key keys[2] =
		{
			{
				.type = TRACEEVAL_TYPE_NUMBER,
				.number = tid,
			},
			{
				.type = TRACEEVAL_TYPE_NUMBER,
				.number = RUNNING,
			}
		};
	ssize_t ret;

	printf("\n    thread id: %d\n", tid);

	printf("      Total run time (us):");
	print_microseconds(14, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);

	keys[1].number = PREEMPT;
	printf("      Total preempt time (us):");
	print_microseconds(10, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);

	keys[1].number = BLOCKED;
	printf("      Total blocked time (us):");
	print_microseconds(10, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);

	keys[1].number = SLEEP;
	printf("      Total sleep time (us):");
	print_microseconds(12, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);
};

static void display_threads(struct traceeval *teval)
{
	struct traceeval_key_array *karray;
	const struct traceeval_key *tkey;
	struct traceeval_key keys[2];
	int last_tid = -1;
	int i, nr;

	nr = traceeval_result_nr(teval);
	if (!nr)
		die("No result for threads\n");

	memset(keys, 0, sizeof(keys));
	keys[1].type = TRACEEVAL_TYPE_NUMBER;

	for (i = 0; i < nr; i++) {
		karray = traceeval_result_indx_key_array(teval, i);
		if (!karray)
			die("No thread key for result %d\n", i);
		tkey = traceeval_key_array_indx(karray, 0);
		if (!tkey)
			die("No thread keys for result?");

		/*
		 * All the TIDS should be together in the results,
		 * as the results are sorted by the first key, which
		 * is the comm.
		 */
		if (last_tid == tkey->number)
			continue;

		last_tid = tkey->number;

		display_thread(teval, tkey->number);
	}
}

static void display_process(struct traceeval *teval, struct process_data *pdata,
			    const char *comm)
{
	struct traceeval_key keys[2] =
		{
			{
				.type = TRACEEVAL_TYPE_STRING,
				.string = comm,
			},
			{
				.type = TRACEEVAL_TYPE_NUMBER,
				.number = RUNNING,
			}
		};
	ssize_t ret;

	printf("Task: %s\n", comm);

	printf("  Total run time (us):");
	print_microseconds(18, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);

	keys[1].number = PREEMPT;
	printf("  Total preempt time (us):");
	print_microseconds(14, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);

	keys[1].number = BLOCKED;
	printf("  Total blocked time (us):");
	print_microseconds(14, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);

	keys[1].number = SLEEP;
	printf("  Total sleep time (us):");
	print_microseconds(16, (ret = traceeval_result_keys_total(teval, keys)) < 0 ? 0 : ret);

	display_threads(pdata->teval_threads);
	display_cpus(pdata->teval_cpus);
	printf("\n");
}

static int compare_pdata(struct traceeval *teval,
			 const struct traceeval_key_array *A,
			 const struct traceeval_key_array *B,
			 void *data)
{
	struct traceeval_key akeys[2];
	struct traceeval_key bkeys[2];
	const struct traceeval_key *akey;
	const struct traceeval_key *bkey;
	long long aval;
	long long bval;
	int ret;

	/* Get the RUNNING values for this process */

	akey = traceeval_key_array_indx(A, 0);
	akeys[0] = *akey;
	akeys[1].type = TRACEEVAL_TYPE_NUMBER;
	akeys[1].number = RUNNING;

	bkey = traceeval_key_array_indx(B, 0);
	bkeys[0] = *bkey;
	bkeys[1].type = TRACEEVAL_TYPE_NUMBER;
	bkeys[1].number = RUNNING;

	aval = traceeval_result_keys_total(teval, akey);
	bval = traceeval_result_keys_total(teval, bkeys);

	if (aval < 0)
		return -1;
	if (bval < 0)
		return -1;

	if (bval < aval)
		return -1;
	if (bval > aval)
		return 1;

	ret = strcmp(bkeys[0].string, akeys[0].string);

	/* If two different processes have the same runtime, sort by name */
	if (ret)
		return ret;

	/* Same process, sort by state */

	akey = traceeval_key_array_indx(A, 1);
	bkey = traceeval_key_array_indx(B, 1);

	if (bkey->number < akey->number)
		return -1;

	return bkey->number > akey->number;
}

static void display_processes(struct traceeval *teval)
{
	struct traceeval_key_array *karray;
	const struct traceeval_key *tkey;
	struct traceeval_key keys[2];
	struct process_data *pdata;
	const char *last_comm = NULL;
	int i, nr;

	nr = traceeval_result_nr(teval);
	if (!nr)
		die("No result for processes\n");

	memset(keys, 0, sizeof(keys));
	keys[1].type = TRACEEVAL_TYPE_NUMBER;

	for (i = 0; i < nr; i++) {
		karray = traceeval_result_indx_key_array(teval, i);
		if (!karray)
			die("No process key for result %d\n", i);
		tkey = traceeval_key_array_indx(karray, 0);
		if (!tkey)
			die("No process keys for result?");

		/*
		 * All the comms should be together in the results,
		 * as the results are sorted by the first key, which
		 * is the comm.
		 */
		if (last_comm && strcmp(tkey->string, last_comm) == 0)
			continue;

		last_comm = tkey->string;

		keys[0] = *tkey;
		keys[1].number = RUNNING;

		/* All processes should have a running state */
		pdata = traceeval_n_get_private(teval, keys);
		if (pdata)
			display_process(teval, pdata, keys[0].string);
	}
}

static void display(struct task_data *tdata)
{
	unsigned long long total_time = 0;
	unsigned long long idle_time = 0;
	struct traceeval_key_array *karray;
	const struct traceeval_key *tkey;
	unsigned long long val;
	int i, nr;

	if (tdata->comm)
		return display_processes(tdata->teval_processes);

	printf("Total:\n");

	nr = traceeval_result_nr(tdata->teval_cpus);
	for (i = 0; i < nr; i++) {
		karray = traceeval_result_indx_key_array(tdata->teval_cpus, i);
		if (!karray)
			die("No CPU keys for result %d\n", i);
		tkey = traceeval_key_array_indx(karray, 1);
		if (!tkey)
			die("No state keys for CPU result %d?", i);

		val = traceeval_result_indx_total(tdata->teval_cpus, i);
		switch (tkey->number) {
		case RUNNING:
			total_time += val;
			break;
		case IDLE:
			idle_time += val;
			break;
		default:
			die("Invalid CPU state: %d\n", tkey->number);
		}
	}

	printf("  Total  run time (us):");
	print_microseconds(16, total_time);
	printf("  Total idle time (us):");
	print_microseconds(16, idle_time);

	display_cpus(tdata->teval_cpus);

	traceeval_sort_custom(tdata->teval_processes, compare_pdata, NULL);

	printf("\n");
	display_processes(tdata->teval_processes);
}

static void free_tdata(struct task_data *tdata)
{
}

int main (int argc, char **argv)
{
	struct tracecmd_input *handle;
	struct task_data data;
	struct traceeval_key_info cpu_tinfo[2] = {
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.name = "CPU"
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.name = "Schedule state"
		}
	};
	struct traceeval_key_info process_tinfo[2] = {
		{
			.type = TRACEEVAL_TYPE_STRING,
			.name = "COMM"
		},
		{
			.type = TRACEEVAL_TYPE_NUMBER,
			.name = "Schedule state"
		}
	};
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

	data.teval_processes = traceeval_2_alloc("Processes", process_tinfo);
	if (!data.teval_processes)
		pdie("Creating trace eval");

	data.teval_cpus = traceeval_2_alloc("CPUs", cpu_tinfo);
	if (!data.teval_cpus)
		pdie("Creating trace eval");

	tracecmd_follow_event(handle, "sched", "sched_switch", switch_func, &data);

	tracecmd_iterate_events(handle, NULL, 0, NULL, NULL);

	display(&data);

	free_tdata(&data);

	return 0;
}
