#include <unistd.h>
#include <sys/wait.h>
#include <trace-cmd.h>
#include <traceeval.h>

struct data {
	struct traceeval		*teval_wakeup;
	struct traceeval		*teval_sched;
};

struct traceeval_type wakeup_keys[] = {
	{
		.name		= "PID",
		.type		= TRACEEVAL_TYPE_NUMBER,
	}
};

struct traceeval_type wakeup_vals[] = {
	{
		.name		= "timestamp",
		.flags		= TRACEEVAL_FL_TIMESTAMP,
		.type		= TRACEEVAL_TYPE_NUMBER_64,
	}
};

struct traceeval_type sched_keys[] = {
	{
		.name		= "COMM",
		.type		= TRACEEVAL_TYPE_STRING,
	},
	{
		.name		= "PID",
		.type		= TRACEEVAL_TYPE_NUMBER,
	}
};

struct traceeval_type sched_vals[] = {
	{
		.name		= "timestamp",
		.flags		= TRACEEVAL_FL_TIMESTAMP,
		.type		= TRACEEVAL_TYPE_NUMBER_64,
	},
	{
		.name		= "delta",
		.flags		= TRACEEVAL_FL_STAT,
		.type		= TRACEEVAL_TYPE_NUMBER_64,
	}
};

static int wakeup_callback(struct tracecmd_input *handle, struct tep_event *event,
			   struct tep_record *record, int cpu, void *d)
{
	static struct tep_format_field *pid_field;
	struct data *data = d;
	unsigned long long val;
	long pid;
	struct traceeval_data keys[1];
	struct traceeval_data vals[1];

	if (!pid_field)
		pid_field = tep_find_field(event, "pid");

	tep_read_number_field(pid_field, record->data, &val);
	pid = val;

	TRACEEVAL_SET_NUMBER(keys[0], pid);
	TRACEEVAL_SET_NUMBER_64(vals[0], record->ts);

	traceeval_insert(data->teval_wakeup, keys, vals);

	return 0;
}

static int sched_callback(struct tracecmd_input *handle, struct tep_event *event,
			   struct tep_record *record, int cpu, void *d)
{
	static struct tep_format_field *next_pid_field;
	static struct tep_format_field *next_comm_field;
	struct data *data = d;
	unsigned long long delta;
	unsigned long long val;
	long pid;
	struct traceeval_data wakeup_keys[1];
	struct traceeval_data keys[2];
	struct traceeval_data vals[2];
	const struct traceeval_data *results;
	const char *comm;

	if (!next_pid_field) {
		next_pid_field = tep_find_field(event, "next_pid");
		next_comm_field = tep_find_field(event, "next_comm");
	}

	tep_read_number_field(next_pid_field, record->data, &val);
	pid = val;

	TRACEEVAL_SET_NUMBER(wakeup_keys[0], pid);

	if (traceeval_query(data->teval_wakeup, wakeup_keys, &results) <= 0)
		return 0;

	delta = record->ts - results[0].number_64;
	traceeval_results_release(data->teval_wakeup, results);

	comm = (char *)record->data + next_comm_field->offset;
	TRACEEVAL_SET_CSTRING(keys[0],comm);
	TRACEEVAL_SET_NUMBER(keys[1], pid);

	TRACEEVAL_SET_NUMBER_64(vals[0], record->ts);
	TRACEEVAL_SET_NUMBER_64(vals[1], delta);

	traceeval_insert(data->teval_sched, keys, vals);

	return 0;
}

static void show_latency(struct data *data)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(data->teval_sched);
	const struct traceeval_data *keys;

	printf("\n");
	while (traceeval_iterator_next(iter, &keys) > 0) {
		struct traceeval_stat *stat;
		unsigned long long val;
		unsigned long long ts;

		stat = traceeval_iterator_stat(iter, sched_vals[1].name);
		if (!stat)
			continue;

		printf("%s-%ld\n", keys[0].string, keys[1].number);

		val = traceeval_stat_max_timestamp(stat, &ts),

		printf("\tmax:%lld at %lld\n", val, ts);

		val = traceeval_stat_min_timestamp(stat, &ts);
		printf("\tmin:%lld at %lld\n", val, ts);
		printf("\ttotal:%lld count:%lld\n",
		       traceeval_stat_total(stat),
		       traceeval_stat_count(stat));
	}
	traceeval_iterator_put(iter);
}

int main (int argc, char **argv)
{
	struct tracecmd_input *handle;
	struct data data;

	if (argc < 2) {
		printf("usage: wake-lat trace.dat\n");
		exit(-1);
	}

	data.teval_wakeup = traceeval_init(wakeup_keys, wakeup_vals);
	data.teval_sched = traceeval_init(sched_keys, sched_vals);

	handle = tracecmd_open(argv[1], TRACECMD_FL_LOAD_NO_PLUGINS);
	if (!handle) {
		perror(argv[0]);
		exit(-1);
	}

	tracecmd_follow_event(handle, "sched", "sched_waking", wakeup_callback, &data);
	tracecmd_follow_event(handle, "sched", "sched_switch", sched_callback, &data);

	tracecmd_iterate_events(handle, NULL, 0, NULL, NULL);

	show_latency(&data);

	return 0;
}
