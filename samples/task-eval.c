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
	       "-B instance - read a buffer instance in the trace.dat file\n"
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

enum sched_state {
	RUNNING,
	BLOCKED,
	PREEMPT,
	SLEEP,
	IDLE,
	ZOMBIE,
	PARKED,
	EXITED,
	DEAD,
	OTHER,
	WAKEUP,
};

/*
 * Keep track of when a CPU is running tasks and when it is
 * idle. Use the CPU number to match the timings in the
 * sched_switch event.
 */
static struct traceeval_type cpu_delta_keys[] = {
	DECLARE_TRACEEVAL_NUMBER("CPU"),
};

/*
 * When scheduling, record the state the CPU was in.
 * It only cares about IDLE vs RUNNING. If the idle task is being
 * scheduled in, mark it the staet as IDLE, otherwise mark it
 * as RUNNING.
 */
static struct traceeval_type cpu_delta_vals[] = {
	DECLARE_TRACEEVAL_NUMBER("Schedule state"),
};

static ssize_t CPU_DELTA_KEY;
static ssize_t CPU_DELTA_STATE;

static void start_cpu_data(struct traceeval *teval, int cpu, int state,
			   unsigned long long ts)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(cpu_delta_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(cpu_delta_vals)];

	TRACEEVAL_SET_NUMBER(keys[CPU_DELTA_KEY], cpu);
	TRACEEVAL_SET_NUMBER(vals[CPU_DELTA_STATE], state);

	traceeval_delta_start(teval, keys, vals, ts);
}

static void continue_cpu_data(struct traceeval *teval, int cpu, int state,
			      unsigned long long ts)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(cpu_delta_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(cpu_delta_vals)];

	TRACEEVAL_SET_NUMBER(keys[CPU_DELTA_KEY], cpu);
	TRACEEVAL_SET_NUMBER(vals[CPU_DELTA_STATE], state);

	traceeval_delta_continue(teval, keys, vals, ts);
}

static int stop_cpu_data(struct traceeval *teval, int cpu, int *state,
			 unsigned long long ts,
			 unsigned long long *delta)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(cpu_delta_keys)];
	const struct traceeval_data *results;
	int ret;

	TRACEEVAL_SET_NUMBER(keys[CPU_DELTA_KEY], cpu);

	ret = traceeval_delta_stop(teval, keys, &results, ts, delta, NULL);
	if (ret < 1)
		return ret;

	if (state)
		*state = results[CPU_DELTA_STATE].number;

	traceeval_results_release(teval, results);
	return 1;
}

int cpu_last_state(struct traceeval *teval, int cpu, int *state)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(cpu_delta_keys)];
	const struct traceeval_data *results;
	int ret;

	TRACEEVAL_SET_NUMBER(keys[CPU_DELTA_KEY], cpu);

	ret = traceeval_delta_query(teval, keys, &results, NULL);
	if (ret < 1)
		return ret;

	*state = results[CPU_DELTA_STATE].number;

	traceeval_results_release(teval, results);
	return 1;
}

/*
 * The output will show all the CPUs and their IDLE vs RUNNING states.
 */
static struct traceeval_type cpu_keys[] = {
	DECLARE_TRACEEVAL_NUMBER("CPU"),
	DECLARE_TRACEEVAL_NUMBER("Schedule state"),
};

/*
 * The mapping of CPU and state will track the timings of how long the
 * CPU was in that state.
 */
static struct traceeval_type cpu_vals[] = {
	DECLARE_TRACEEVAL_DELTA(DELTA_NAME),
};

static ssize_t CPU_KEY;
static ssize_t CPU_STATE;
static ssize_t CPU_DELTA;

static void insert_cpu_data(struct traceeval *teval, int cpu, int state,
			    unsigned long long delta, unsigned long long ts)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(cpu_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(cpu_vals)];

	TRACEEVAL_SET_NUMBER(keys[CPU_KEY], cpu);
	TRACEEVAL_SET_NUMBER(keys[CPU_STATE], state);

	TRACEEVAL_SET_DELTA(vals[CPU_DELTA], delta, ts);

	traceeval_insert(teval, keys, vals);
}

/*
 * When tracking tasks and threads wake up timings.
 */
static struct traceeval_type wakeup_delta_keys[] = {
	DECLARE_TRACEEVAL_NUMBER("PID"),
};

/*
 * When finishing the timings of the task being woken up.
 */
static struct traceeval_type wakeup_delta_vals[] = {
	DECLARE_TRACEEVAL_STRING("COMM"),
	DECLARE_TRACEEVAL_NUMBER("Prio"),
};

static ssize_t WAKEUP_DELTA_PID;
static ssize_t WAKEUP_DELTA_COMM;
static ssize_t WAKEUP_DELTA_PRIO;

static void start_wakeup_data(struct traceeval *teval, int pid,
			      const char *comm, int prio, unsigned long long ts)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(wakeup_delta_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(wakeup_delta_vals)];

	TRACEEVAL_SET_NUMBER(keys[WAKEUP_DELTA_PID], pid);

	TRACEEVAL_SET_CSTRING(vals[WAKEUP_DELTA_COMM], comm);
	TRACEEVAL_SET_NUMBER(vals[WAKEUP_DELTA_PRIO], prio);

	traceeval_delta_start(teval, keys, vals, ts);
}

static int stop_wakeup_data(struct traceeval *teval, int pid,
			    const char **comm, int *prio, unsigned long long ts,
			    unsigned long long *delta)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(wakeup_delta_keys)];
	const struct traceeval_data *results;
	int ret;

	TRACEEVAL_SET_NUMBER(keys[WAKEUP_DELTA_PID], pid);

	ret = traceeval_delta_stop(teval, keys, &results, ts, delta, NULL);
	if (ret < 1)
		return ret;

	if (comm)
		*comm = results[WAKEUP_DELTA_COMM].string;

	if (prio)
		*prio = results[WAKEUP_DELTA_PRIO].number;

	traceeval_results_release(teval, results);
	return 1;
}

/*
 * When tracking tasks and threads, remember the task id (PID)
 * when scheduling out (for sleep state) or in (for running state).
 */
static struct traceeval_type task_delta_keys[] = {
	DECLARE_TRACEEVAL_NUMBER("PID"),
};

/*
 * When finishing the timings, will need the name of the task, the
 * state it was in:  (RUNNING, PREEMPTED, BLOCKED, IDLE, or other)
 * and the priority it had. This will be saved for the output.
 */
static struct traceeval_type task_delta_vals[] = {
	DECLARE_TRACEEVAL_NUMBER("Schedule state"),
	DECLARE_TRACEEVAL_STRING("COMM"),
	DECLARE_TRACEEVAL_NUMBER("Prio"),
};

static ssize_t TASK_DELTA_PID;
static ssize_t TASK_DELTA_STATE;
static ssize_t TASK_DELTA_COMM;
static ssize_t TASK_DELTA_PRIO;

static void start_task_data(struct traceeval *teval, int pid, int state,
			    const char *comm, int prio, unsigned long long ts)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(task_delta_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(task_delta_vals)];

	TRACEEVAL_SET_NUMBER(keys[TASK_DELTA_PID], pid);

	TRACEEVAL_SET_NUMBER(vals[TASK_DELTA_STATE], state);
	TRACEEVAL_SET_CSTRING(vals[TASK_DELTA_COMM], comm);
	TRACEEVAL_SET_NUMBER(vals[TASK_DELTA_PRIO], prio);

	traceeval_delta_start(teval, keys, vals, ts);
}

static int stop_task_data(struct traceeval *teval, int pid, int *state,
			  const char **comm, int *prio, unsigned long long ts,
			  unsigned long long *delta, unsigned long long *save_ts)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(task_delta_keys)];
	const struct traceeval_data *results;
	int ret;

	TRACEEVAL_SET_NUMBER(keys[TASK_DELTA_PID], pid);

	ret = traceeval_delta_stop(teval, keys, &results, ts, delta, save_ts);
	if (ret < 1)
		return ret;

	if (state)
		*state = results[TASK_DELTA_STATE].number;

	if (comm)
		*comm = results[TASK_DELTA_COMM].string;

	if (prio)
		*prio = results[TASK_DELTA_PRIO].number;

	traceeval_results_release(teval, results);
	return 1;
}

/*
 * Will output all the processes by their names. This means the two
 * tasks with the same name will be grouped together (even though they
 * may not be threads). The tasks will also be broken up by what state
 * they were in: RUNNING, BLOCKED, PREEMPTED, SLEEPING.
 */
static struct traceeval_type task_keys[] = {
	DECLARE_TRACEEVAL_STRING("COMM"),
	DECLARE_TRACEEVAL_NUMBER("Schedule state"),
};

static void release_data(const struct traceeval_type *type,
			  struct traceeval_data *data);

static int copy_data(const struct traceeval_type *type,
		     struct traceeval_data *dst,
		     const struct traceeval_data *src)
{
	if (dst->pointer && dst->pointer != src->pointer)
		die("Pointers do not match!");
	/* This prevents releases of data */
	*dst = *src;
	return 0;
}

/*
 * For each state the process is in, record the time delta for
 * that state. Also, only for the RUNNING state, this will
 * daisy chain another traceeval for each thread. That is,
 * for each unique thread id (PID), there will be a traceeval
 * histogram of those threads denoted by the teval_thread, and
 * that will be saved in the "data" field.
 */
static struct traceeval_type task_vals[] = {
	DECLARE_TRACEEVAL_POINTER("data", release_data, copy_data),
	DECLARE_TRACEEVAL_DELTA(DELTA_NAME),
};

static ssize_t TASK_COMM;
static ssize_t TASK_STATE;
static ssize_t TASK_DATA;
static ssize_t TASK_DELTA;

static int insert_task_data(struct traceeval *teval, const char *comm,
			     int state, void *data, unsigned long long delta,
			     unsigned long long timestamp)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(task_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(task_vals)];

	TRACEEVAL_SET_CSTRING(keys[TASK_COMM], comm);
	TRACEEVAL_SET_NUMBER(keys[TASK_STATE], state);

	/*
	 * Can not have data stored more than once, only save it for
	 * the RUNNING state.
	 */
	if (state != RUNNING)
		data = NULL;

	TRACEEVAL_SET_POINTER(vals[TASK_DATA], data);
	TRACEEVAL_SET_DELTA(vals[TASK_DELTA], delta, timestamp);

	return traceeval_insert(teval, keys, vals);
}

static bool task_data_exists(struct traceeval *teval, const char *comm, void **data)
{
	const struct traceeval_data *results;
	struct traceeval_data keys[] = {
		DEFINE_TRACEEVAL_CSTRING(	comm	),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING	),
	};
	int ret;

	ret = traceeval_query(teval, keys, &results);
	if (ret > 0) {
		if (data)
			*data = results[0].pointer;
		traceeval_results_release(teval, results);
		return true;
	}
	if (ret < 0)
		pdie("Could not query process data");

	return false;
}

/*
 * Each recorded process will have a traceeval to save all the
 * threads within it. The threads will be mapped by their TID (PID)
 * the state they were in: RUNNING, BLOCKED, PREEMPTED, SLEEPING
 * and their priority.
 */
static struct traceeval_type thread_keys[] = {
	DECLARE_TRACEEVAL_NUMBER("TID"),
	DECLARE_TRACEEVAL_NUMBER("Prio"),
	DECLARE_TRACEEVAL_NUMBER("Schedule state"),
};

/*
 * Save the timings of the thread/state/prio keys.
 */
static struct traceeval_type thread_vals[] = {
	DECLARE_TRACEEVAL_DELTA(DELTA_NAME),
};

static ssize_t THREAD_TID;
static ssize_t THREAD_PRIO;
static ssize_t THREAD_STATE;
static ssize_t THREAD_DELTA;

static void insert_thread_data(struct traceeval *teval,
			       int tid, int state, int prio,
			       unsigned long long delta,
			       unsigned long long timestamp)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(thread_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(thread_vals)];

	TRACEEVAL_SET_NUMBER(keys[THREAD_TID], tid);
	TRACEEVAL_SET_NUMBER(keys[THREAD_PRIO], prio);
	TRACEEVAL_SET_NUMBER(keys[THREAD_STATE], state);

	TRACEEVAL_SET_DELTA(vals[THREAD_DELTA], delta, timestamp);

	traceeval_insert(teval, keys, vals);
}

static struct traceeval_type wakeup_task_keys[] = {
	DECLARE_TRACEEVAL_STRING("COMM"),
};

static struct traceeval_type wakeup_thread_keys[] = {
	DECLARE_TRACEEVAL_NUMBER("PID"),
	DECLARE_TRACEEVAL_NUMBER("Prio"),
};

static struct traceeval_type wakeup_vals[] = {
	DECLARE_TRACEEVAL_DELTA(DELTA_NAME),
};

static ssize_t WAKEUP_TASK_COMM;
static ssize_t WAKEUP_THREAD_PID;
static ssize_t WAKEUP_THREAD_PRIO;
static ssize_t WAKEUP_DELTA;

#define assign_type(type, name, array) \
	if ((type = traceeval_type_index(name, array)) < 0)	\
		die("Invalid index %s for %s", name, #type);

static void init_indexes(void)
{
	assign_type(CPU_DELTA_KEY, "CPU", cpu_delta_keys);
	assign_type(CPU_DELTA_STATE, "Schedule state", cpu_delta_vals);

	assign_type(CPU_KEY, "CPU", cpu_keys);
	assign_type(CPU_STATE, "Schedule state", cpu_keys);
	assign_type(CPU_DELTA, DELTA_NAME, cpu_vals);

	assign_type(WAKEUP_DELTA_PID, "PID", wakeup_delta_keys);
	assign_type(WAKEUP_DELTA_COMM, "COMM", wakeup_delta_vals);
	assign_type(WAKEUP_DELTA_PRIO, "Prio", wakeup_delta_vals);

	assign_type(TASK_DELTA_PID, "PID", task_delta_keys);
	assign_type(TASK_DELTA_STATE, "Schedule state", task_delta_vals);
	assign_type(TASK_DELTA_COMM, "COMM", task_delta_vals);
	assign_type(TASK_DELTA_PRIO, "Prio", task_delta_vals);

	assign_type(TASK_COMM, "COMM", task_keys);
	assign_type(TASK_STATE, "Schedule state", task_keys);
	assign_type(TASK_DATA, "data", task_vals);
	assign_type(TASK_DELTA, DELTA_NAME, task_vals);

	assign_type(THREAD_TID, "TID", thread_keys);
	assign_type(THREAD_PRIO, "Prio", thread_keys);
	assign_type(THREAD_STATE, "Schedule state", thread_keys);
	assign_type(THREAD_DELTA, DELTA_NAME, thread_vals);

	assign_type(WAKEUP_TASK_COMM, "COMM", wakeup_task_keys);
	assign_type(WAKEUP_THREAD_PID, "PID", wakeup_thread_keys);
	assign_type(WAKEUP_THREAD_PRIO, "Prio", wakeup_thread_keys);
	assign_type(WAKEUP_DELTA, DELTA_NAME, wakeup_vals)
}

static void insert_wakeup_task_data(struct traceeval *teval,
				    const char *comm,
				    unsigned long long delta,
				    unsigned long long timestamp)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(wakeup_task_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(wakeup_vals)];

	TRACEEVAL_SET_CSTRING(keys[WAKEUP_TASK_COMM], comm);

	TRACEEVAL_SET_DELTA(vals[WAKEUP_DELTA], delta, timestamp);

	traceeval_insert(teval, keys, vals);
}

static void insert_wakeup_thread_data(struct traceeval *teval,
				      int tid, int prio,
				      unsigned long long delta,
				      unsigned long long timestamp)
{
	struct traceeval_data keys[TRACEEVAL_ARRAY_SIZE(wakeup_thread_keys)];
	struct traceeval_data vals[TRACEEVAL_ARRAY_SIZE(wakeup_vals)];

	TRACEEVAL_SET_NUMBER(keys[WAKEUP_THREAD_PID], tid);
	TRACEEVAL_SET_NUMBER(keys[WAKEUP_THREAD_PRIO], prio);

	TRACEEVAL_SET_DELTA(vals[WAKEUP_DELTA], delta, timestamp);

	traceeval_insert(teval, keys, vals);
}

struct process_data {
	struct traceeval	*teval_cpus;
	struct traceeval	*teval_threads;
	struct traceeval	*teval_wakeup;
};

struct task_data {
	struct traceeval	*teval_cpus;
	struct traceeval	*teval_tasks;
	struct traceeval	*teval_wakeup;
	unsigned long long	last_ts;
	char			*comm;
};

enum command {
	START,
	STOP
};

static void release_data(const struct traceeval_type *type,
			  struct traceeval_data *data)
{
	struct process_data *pdata;

	if (!data || !data->pointer)
		return;

	pdata = data->pointer;
	traceeval_release(pdata->teval_cpus);
	traceeval_release(pdata->teval_threads);
	traceeval_release(pdata->teval_wakeup);
	free(pdata);
	data->pointer = NULL;
}

static void init_process_data(struct process_data *pdata)
{
	pdata->teval_cpus = traceeval_init(cpu_keys, cpu_vals);
	if (!pdata->teval_cpus)
		pdie("Creating trace eval cpus");

	pdata->teval_threads = traceeval_init(thread_keys, thread_vals);
	if (!pdata->teval_threads)
		pdie("Creating trace eval threads");

	pdata->teval_wakeup = traceeval_init(wakeup_thread_keys, wakeup_vals);
	if (!pdata->teval_wakeup)
		pdie("Creating trace eval wakeup");
}

void set_process_data(struct task_data *tdata, const char *comm, void *data)
{
	int ret;

	if (task_data_exists(tdata->teval_tasks, comm, NULL))
		return;

	ret = insert_task_data(tdata->teval_tasks, comm, RUNNING, data, 0, 0);
	if (ret < 0)
		pdie("Failed to set process data");
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

/*
 * Each process will have a traceeval for all their threads. The
 * thread traceeval descriptor will be saved in the process/RUNNING
 * field. If a process is never running, then it will not have any
 * threads!
 */
static struct process_data *
get_process_data(struct task_data *tdata, const char *comm)
{
	void *data;

	if (!task_data_exists(tdata->teval_tasks, comm, &data))
		return alloc_pdata(tdata, comm);

	return data;
}

/*
 * When a CPU is scheduling in idle, record the running state,
 * and start the idle timings.
 */
static void update_cpu_to_idle(struct task_data *tdata, struct tep_record *record)
{
	unsigned long long delta;
	int state;
	int ret;

	/* Finish previous run */
	ret = stop_cpu_data(tdata->teval_cpus, record->cpu, &state,
			    record->ts, &delta);
	if (ret > 0)
		insert_cpu_data(tdata->teval_cpus, record->cpu, state,
				delta, record->ts);

	/* Start the next state */
	start_cpu_data(tdata->teval_cpus, record->cpu, IDLE, record->ts);
}

/*
 * When a CPU is scheduling a task, if idle is scheduling out, stop
 * the idle timings and start or continue the running timings.
 */
static void update_cpu_to_running(struct task_data *tdata, struct tep_record *record)
{
	unsigned long long delta;
	int state;
	int ret;

	/* Test if the CPU was idle */
	ret = cpu_last_state(tdata->teval_cpus, record->cpu, &state);
	if (ret > 0 && state == IDLE) {
		/* Coming from idle */
		stop_cpu_data(tdata->teval_cpus, record->cpu, NULL,
				    record->ts, &delta);

		/* Update the idle teval */
		insert_cpu_data(tdata->teval_cpus, record->cpu, IDLE, delta, record->ts);
	}

	/* Continue with the CPU running */
	continue_cpu_data(tdata->teval_cpus, record->cpu, RUNNING, record->ts);
}

static void update_thread(struct task_data *tdata, int pid, const char *comm,
			  enum sched_state state, int prio, unsigned long long delta,
			  unsigned long long ts)
{
	struct process_data *pdata;
	int ret;

	pdata = get_process_data(tdata, comm);

	insert_thread_data(pdata->teval_threads, pid, state, prio, delta, ts);

	/* Also update the process */
	insert_task_data(tdata->teval_tasks, comm, state, pdata, delta, ts);

	ret = stop_wakeup_data(tdata->teval_wakeup, pid, &comm, &prio, ts, &delta);
	if (ret < 1)
		return;
	insert_wakeup_task_data(tdata->teval_wakeup, comm, delta, ts);
	insert_wakeup_thread_data(pdata->teval_wakeup, pid, prio, delta, ts);
}

static void start_running_thread(struct task_data *tdata,
				 struct tep_record *record,
				 const char *comm, int pid, int prio)
{
	unsigned long long delta;
	unsigned long long val;
	int state;
	int ret;

	ret = stop_task_data(tdata->teval_tasks, pid, &state,
			     NULL, NULL, record->ts, &delta, &val);
	if (ret > 0) {
		if (state == RUNNING)
			die("State %d is running! %lld -> %lld", pid, val, record->ts);
		update_thread(tdata, pid, comm, state, prio, delta, record->ts);
	}

	/* This task is running, so start timing the running portion */
	start_task_data(tdata->teval_tasks, pid, RUNNING, comm, prio, record->ts);
}

static int get_stop_state(unsigned long long val)
{
	if (val & 1)
		return SLEEP;
	if (val & 2)
		return BLOCKED;
	if (val & 0x10)
		return ZOMBIE;
	if (val & 0x20)
		return EXITED;
	if (val & 0x40)
		return PARKED;
	if (val & 0x80)
		return DEAD;
	return PREEMPT;
}

static void sched_out(struct task_data *tdata, const char *comm,
		      struct tep_event *event,
		      struct tep_record *record, struct tep_format_field *prev_pid,
		      struct tep_format_field *prev_state,
		      struct tep_format_field *prev_prio)
{
	struct process_data *pdata;
	unsigned long long delta;
	unsigned long long val;
	int state;
	int old_state;
	int prio;
	int pid;
	int ret;

	ret = tep_read_number_field(prev_pid, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch prev_pid for record");
	pid = val;

	/* Idle is handled by sched_in() */
	if (!pid)
		return;

	ret = tep_read_number_field(prev_prio, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch prev_prio for record");
	prio = val;

	ret = tep_read_number_field(prev_state, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_pid for record");
	state = get_stop_state(val);

	/* Stop the RUNNING timings of the tasks that is scheduling out */
	ret = stop_task_data(tdata->teval_tasks, pid, &old_state, NULL, NULL,
			     record->ts, &delta, &val);

	/* Start timing the task while it's off the CPU */
	start_task_data(tdata->teval_tasks, pid, state, comm, prio, record->ts);

	/*
	 * If a wakeup happened when the task was running, do not record
	 * the wakeup latency.
	 */
	stop_wakeup_data(tdata->teval_wakeup, pid, NULL, NULL, record->ts, NULL);

	if (ret <= 0)
		return;

	/* What is scheduling out should be considered "running" */
	if (old_state != RUNNING)
		die("Not running %d from %lld to %lld",
		    old_state, val, record->ts);

	/* Now add the "running" timing of the thread that scheduled out */

	pdata = get_process_data(tdata, comm);

	insert_task_data(tdata->teval_tasks, comm, RUNNING, pdata, delta, record->ts);

	/* Update the individual thread as well */

	insert_thread_data(pdata->teval_threads, pid, RUNNING, prio, delta, record->ts);
	insert_cpu_data(pdata->teval_cpus, record->cpu, RUNNING, delta, record->ts);
}

static void sched_in(struct task_data *tdata, const char *comm,
		     struct tep_event *event,
		     struct tep_record *record,
		     struct tep_format_field *next_pid,
		     struct tep_format_field *next_prio)
{
	unsigned long long val;
	int prio;
	int pid;
	int ret;

	ret = tep_read_number_field(next_pid, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_pid for record");
	pid = val;

	/* Idle task */
	if (!pid) {
		update_cpu_to_idle(tdata, record);
		return;
	}

	ret = tep_read_number_field(next_prio, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch next_prio for record");
	prio = val;

	/* Continue measuring CPU running time */
	update_cpu_to_running(tdata, record);
	start_running_thread(tdata, record, comm, pid, prio);
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
	static struct tep_format_field *prev_prio;
	static struct tep_format_field *next_comm;
	static struct tep_format_field *next_pid;
	static struct tep_format_field *next_prio;
	struct task_data *tdata = data;
	const char *comm;

	if (!next_comm) {
		prev_comm = get_field(event, "prev_comm");
		prev_pid = get_field(event, "prev_pid");
		prev_state = get_field(event, "prev_state");
		prev_prio = get_field(event, "prev_prio");

		next_comm = get_field(event, "next_comm");
		next_pid = get_field(event, "next_pid");
		next_prio = get_field(event, "next_prio");
	}

	comm = record->data + prev_comm->offset;
	if (!tdata->comm || strcmp(comm, tdata->comm) == 0)
		sched_out(tdata, comm, event, record, prev_pid, prev_state, prev_prio);

	comm = record->data + next_comm->offset;
	if (!tdata->comm || strcmp(comm, tdata->comm) == 0)
		sched_in(tdata, comm, event, record, next_pid, next_prio);

	return 0;
}

static int wakeup_func(struct tracecmd_input *handle, struct tep_event *event,
		       struct tep_record *record, int cpu, void *data)
{
	static struct tep_format_field *comm_field;
	static struct tep_format_field *pid_field;
	static struct tep_format_field *prio_field;
	struct task_data *tdata = data;
	unsigned long long val;
	const char *comm;
	int prio;
	int pid;
	int ret;

	if (!comm_field) {
		comm_field = get_field(event, "comm");
		pid_field = get_field(event, "pid");
		prio_field = get_field(event, "prio");
	}

	comm = record->data + comm_field->offset;
	if (tdata->comm && strcmp(comm, tdata->comm) != 0)
		return 0;

	ret = tep_read_number_field(pid_field, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch pid for record");
	pid = val;

	ret = tep_read_number_field(prio_field, record->data, &val);
	if (ret < 0)
		die("Could not read sched_switch prio for record");
	prio = val;

	start_wakeup_data(tdata->teval_wakeup, pid, comm, prio, record->ts);
	return 0;
}

static void print_microseconds(int idx, unsigned long long nsecs)
{
	unsigned long long usecs;

	usecs = nsecs / 1000;
	if (!nsecs || usecs)
		printf("%*lld", idx, usecs);
	else
		printf("%*d.%03lld", idx, 0, nsecs);
}

static void print_microseconds_nl(int idx, unsigned long long nsecs)
{
	print_microseconds(idx, nsecs);
	printf("\n");
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
		DEFINE_TRACEEVAL_CSTRING(	Akeys[TASK_COMM].cstring	),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING				), };
	struct traceeval_data keysB[] = {
		DEFINE_TRACEEVAL_CSTRING(	Bkeys[TASK_COMM].cstring	),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING				), };
	struct traceeval_stat *statA;
	struct traceeval_stat *statB;
	unsigned long long totalA = -1;
	unsigned long long totalB = -1;

	/* First check if we are on the same task */
	if (strcmp(Akeys[TASK_COMM].cstring, Bkeys[TASK_COMM].cstring) == 0) {
		/* Sort decending */
		if (Bkeys[TASK_STATE].number > Akeys[TASK_STATE].number)
			return -1;
		return Bkeys[TASK_STATE].number != Akeys[TASK_STATE].number;
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

	return strcmp(Bkeys[TASK_COMM].cstring, Akeys[TASK_COMM].cstring);
}

static void display_cpus(struct traceeval *teval)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(teval);
	unsigned long long max, max_ts, min, min_ts;
	const struct traceeval_data *keys;
	struct traceeval_stat *stat;
	int last_cpu = -1;

	if (!iter)
		pdie("Could not get iterator?");

	printf("\n");

	traceeval_iterator_sort(iter, cpu_keys[CPU_KEY].name, 0, true);
	traceeval_iterator_sort(iter, cpu_keys[CPU_STATE].name, 1, true);

	while (traceeval_iterator_next(iter, &keys) > 0) {
		int state = keys[CPU_STATE].number;
		int cpu = keys[CPU_KEY].number;

		stat = traceeval_iterator_stat(iter, DELTA_NAME);
		if (!stat)
			continue; // die?

		max = traceeval_stat_max_timestamp(stat, &max_ts);
		min = traceeval_stat_min_timestamp(stat, &min_ts);

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
		print_microseconds_nl(12, traceeval_stat_total(stat));
		printf("              average (us):");
		print_microseconds_nl(12, traceeval_stat_average(stat));
		printf("                       max:");
		print_microseconds(12, max);
		printf("\tat: %lld\n", max_ts);
		printf("                       min:");
		print_microseconds(12, min);
		printf("\tat: %lld\n", min_ts);
		printf("                     count: %*lld\n", 11,
			traceeval_stat_count(stat));
		printf("                   stddev: %*.3f\n", 16,
		       traceeval_stat_stddev(stat) / 1000);

		last_cpu = cpu;
	}

	if (last_cpu < 0)
		die("No result for CPUs\n");

	traceeval_iterator_put(iter);
}

static void print_stats(int idx, struct traceeval_stat *stat)
{
	unsigned long long total, max, min, cnt, max_ts, min_ts;

	if (stat) {
		total = traceeval_stat_total(stat);
		max = traceeval_stat_max_timestamp(stat, &max_ts);
		min = traceeval_stat_min_timestamp(stat, &min_ts);
		cnt = traceeval_stat_count(stat);
	} else {
		total = max = max_ts = min = min_ts = cnt = 0;
	}

	if (!cnt) {
		print_microseconds_nl(idx, total);
	} else if (cnt == 1) {
		print_microseconds(idx, total);
		printf("\tat: %lld\n", max_ts);
	} else {
		print_microseconds_nl(idx, total);
		printf("%*s", 40 - idx, "average:");
		print_microseconds_nl(idx, traceeval_stat_average(stat));
		printf("%*s", 40 - idx, "max:");
		print_microseconds(idx, max);
		printf("\tat: %lld\n", max_ts);
		printf("%*s", 40 - idx, "min:");
		print_microseconds(idx, min);
		printf("\tat: %lld\n", min_ts);
		printf("%*s%*lld\n", 40 - idx, "count:", idx, cnt);
		printf("%*s%*.3f\n", 40 - idx, "stddev:", idx + 4,
		       traceeval_stat_stddev(stat) / 1000);
	}
}

static void display_state_times(int state, struct traceeval_stat *stat)
{
	switch (state) {
	case RUNNING:
		printf("      Total run time (us):");
		print_stats(14, stat);
		break;
	case BLOCKED:
		printf("      Total blocked time (us):");
		print_stats(10, stat);
		break;
	case PREEMPT:
		printf("      Total preempt time (us):");
		print_stats(10, stat);
		break;
	case SLEEP:
		printf("      Total sleep time (us):");
		print_stats(12, stat);
		break;
	case WAKEUP:
		printf("      Total wakeup time (us):");
		print_stats(11, stat);
		break;
	}
}

static void display_threads(struct traceeval *teval, struct traceeval *wake_teval)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(teval);
	const struct traceeval_data *keys;
	struct traceeval_stat *stat;
	int last_tid = -1;
	int last_prio = -1;

	/* PID */
	traceeval_iterator_sort(iter, thread_keys[THREAD_TID].name, 0, true);

	/* PRIO */
	traceeval_iterator_sort(iter, thread_keys[THREAD_PRIO].name, 1, true);

	/* STATE */
	traceeval_iterator_sort(iter, thread_keys[THREAD_STATE].name, 2, true);

	while (traceeval_iterator_next(iter, &keys) > 0) {
		int tid = keys[THREAD_TID].number;
		int prio = keys[THREAD_PRIO].number;
		int state = keys[THREAD_STATE].number;

		stat = traceeval_iterator_stat(iter, DELTA_NAME);
		if (!stat)
			continue; // die?

		if (last_tid != tid || last_prio != prio) {
			if (prio < 120)
				printf("\n    thread id: %d [ prio: %d ]\n", tid, prio);
			else
				printf("\n    thread id: %d\n", tid);
		}

		last_tid = tid;
		last_prio = prio;

		display_state_times(state, stat);

		if (state != RUNNING)
			continue;

		stat = traceeval_stat_size(wake_teval, keys, 2, DELTA_NAME);
		if (!stat)
			continue;
		display_state_times(WAKEUP, stat);
	}

	traceeval_iterator_put(iter);

	if (last_tid < 0)
		die("No result for threads\n");
}

static void display_process(struct process_data *pdata)
{
	display_threads(pdata->teval_threads, pdata->teval_wakeup);
	display_cpus(pdata->teval_cpus);
	printf("\n");
}

static void display_process_stats(struct traceeval *teval, struct traceeval *wake_teval,
				  struct process_data *pdata, const char *comm)
{
	struct traceeval_stat *stat;
	struct traceeval_data keys[] = {
		DEFINE_TRACEEVAL_CSTRING(	comm		),
		DEFINE_TRACEEVAL_NUMBER(	RUNNING		),
	};

	for (int i = 0; i < OTHER; i++) {
		TRACEEVAL_SET_NUMBER(keys[1], i);

		stat = traceeval_stat(teval, keys, DELTA_NAME);
		display_state_times(i, stat);

		if (i != RUNNING)
			continue;

		stat = traceeval_stat_size(wake_teval, keys, 1, DELTA_NAME);
		if (!stat)
			continue;
		display_state_times(WAKEUP, stat);
	}
}

static void display_processes(struct traceeval *teval, struct traceeval *wake_teval)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(teval);
	const struct traceeval_data *keys;
	const char *last_comm = "";
	int ret;

	traceeval_iterator_sort_custom(iter, compare_pdata, NULL);

	while (traceeval_iterator_next(iter, &keys) > 0) {
		const struct traceeval_data *results;
		struct process_data *pdata = NULL;
		const char *comm = keys[TASK_COMM].cstring;

		if (strcmp(comm, last_comm) == 0)
			continue;

		last_comm = comm;

		ret = traceeval_iterator_query(iter, &results);
		if (ret < 0)
			pdie("Could not query iterator");
		if (ret < 1)
			continue; /* ?? */

		pdata = results[TASK_DATA].pointer;
		traceeval_results_release(teval, results);

		printf("Task: %s\n", comm);

		display_process_stats(teval, wake_teval, pdata, comm);
		if (pdata)
			display_process(pdata);
	}
	traceeval_iterator_put(iter);
}

static void display(struct task_data *tdata)
{
	struct traceeval *teval = tdata->teval_cpus;
	struct traceeval_iterator *iter;
	const struct traceeval_data *keys;
	struct traceeval_stat *stat;
	unsigned long long total_time = 0;
	unsigned long long idle_time = 0;

	if (tdata->comm) {
		return display_processes(tdata->teval_tasks, tdata->teval_wakeup);
	}

	iter = traceeval_iterator_get(teval);

	printf("Total:\n");

	if (!iter)
		pdie("No cpus?");

	while (traceeval_iterator_next(iter, &keys) > 0) {
		int state = keys[CPU_STATE].number;

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

	traceeval_iterator_put(iter);

	printf("  Total  run time (us):");
	print_microseconds_nl(16, total_time);
	printf("  Total idle time (us):");
	print_microseconds_nl(16, idle_time);

	display_cpus(tdata->teval_cpus);

	printf("\n");
	display_processes(tdata->teval_tasks, tdata->teval_wakeup);
}

static void free_tdata(struct task_data *tdata)
{
	if (!tdata)
		return;

	traceeval_release(tdata->teval_cpus);
	traceeval_release(tdata->teval_tasks);
	traceeval_release(tdata->teval_wakeup);
}

/*
 * When the trace ended, there was likely tasks still running on
 * the CPU (or sleeping). Just stop all the timings and put them
 * into the database as well.
 */
static void finish_leftovers(struct task_data *data)
{
	const struct traceeval_data *results;
	const struct traceeval_data *keys;
	struct traceeval_iterator *iter;
	unsigned long long delta;
	enum sched_state state;
	const char *comm;
	int prio;
	int pid;

	iter = traceeval_iterator_delta_start_get(data->teval_tasks);
	while (traceeval_iterator_next(iter, &keys) > 0) {
		traceeval_iterator_delta_stop(iter, &results, data->last_ts,
					      &delta, NULL);

		pid = keys[TASK_DELTA_PID].number;

		state = results[TASK_DELTA_STATE].number;
		comm = results[TASK_DELTA_COMM].cstring;
		prio = results[TASK_DELTA_PRIO].number;

		update_thread(data, pid, comm, state, prio, delta, data->last_ts);
	}
	traceeval_iterator_put(iter);

	iter = traceeval_iterator_delta_start_get(data->teval_cpus);
	while (traceeval_iterator_next(iter, &keys) > 0) {
		traceeval_iterator_delta_stop(iter, &results, data->last_ts,
					      &delta, NULL);
		insert_cpu_data(data->teval_cpus, keys[0].number, results[0].number,
				delta, data->last_ts);
		traceeval_iterator_results_release(iter, results);
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
	const char *buffer = NULL;
	int c;

	memset(&data, 0, sizeof(data));

	argv0 = argv[0];

	while ((c = getopt(argc, argv, "c:B:h")) >= 0) {
		switch (c) {
		case 'c':
			data.comm = optarg;
			break;
		case 'B':
			buffer = optarg;
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

	init_indexes();

	handle = tracecmd_open(argv[0], TRACECMD_FL_LOAD_NO_PLUGINS);
	if (!handle)
		pdie("Error opening %s", argv[0]);

	if (buffer) {
		int bufs;
		int i;

		bufs = tracecmd_buffer_instances(handle);
		for (i = 0; i < bufs; i++) {
			const char *name;

			name = tracecmd_buffer_instance_name(handle, i);
			if (name && strcmp(name, buffer) == 0) {
				handle = tracecmd_buffer_instance_handle(handle, i);
				break;
			}
		}
		if (i == bufs)
			die("Can not find instance %s\n", buffer);
	}

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

	data.teval_wakeup = traceeval_init(wakeup_task_keys, wakeup_vals);
	if (!data.teval_wakeup)
		pdie("Creating trace eval wakeup");

	if (traceeval_delta_create(data.teval_wakeup, wakeup_delta_keys, wakeup_delta_vals) < 0)
		pdie("Creating trace delta wakeup");

	tracecmd_follow_event(handle, "sched", "sched_switch", switch_func, &data);
	tracecmd_follow_event(handle, "sched", "sched_waking", wakeup_func, &data);

	tracecmd_iterate_events(handle, NULL, 0, event_callback, &data);

	finish_leftovers(&data);

	display(&data);

	free_tdata(&data);

	return 0;
}
