#include <unistd.h>
#include <sys/wait.h>
#include <trace-cmd.h>
#include <traceeval.h>

struct data {
	struct traceeval		*teval;
};

struct traceeval_type delta_keys[] = {
	{
		.name		= "PID",
		.type		= TRACEEVAL_TYPE_NUMBER,
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
		.name		= "delta",
		.type		= TRACEEVAL_TYPE_DELTA,
	},
};

static int wakeup_callback(struct tracecmd_input *handle, struct tep_event *event,
			   struct tep_record *record, int cpu, void *d)
{
	static struct tep_format_field *pid_field;
	struct traceeval_data keys[1];
	struct data *data = d;
	unsigned long long val;
	long pid;

	if (!pid_field) {
		pid_field = tep_find_field(event, "pid");
	}

	tep_read_number_field(pid_field, record->data, &val);
	pid = val;

	TRACEEVAL_SET_NUMBER(keys[0], pid);

	traceeval_delta_start(data->teval, keys, NULL, record->ts);

	return 0;
}

static int sched_callback(struct tracecmd_input *handle, struct tep_event *event,
			   struct tep_record *record, int cpu, void *d)
{
	static struct tep_format_field *next_pid_field;
	static struct tep_format_field *next_comm_field;
	struct data *data = d;
	struct traceeval_data delta_keys[1];
	struct traceeval_data sched_keys[2];
	struct traceeval_data vals[1];
	unsigned long long val;
	const char *comm;
	long pid;
	int ret;

	if (!next_pid_field) {
		next_pid_field = tep_find_field(event, "next_pid");
		next_comm_field = tep_find_field(event, "next_comm");
	}

	tep_read_number_field(next_pid_field, record->data, &val);
	pid = val;

	comm = (char *)record->data + next_comm_field->offset;

	TRACEEVAL_SET_NUMBER(delta_keys[0], pid);
	ret = traceeval_delta_stop(data->teval, delta_keys, NULL, record->ts, &val, NULL);
	if (ret <= 0)
		return 0;

	TRACEEVAL_SET_CSTRING(sched_keys[0],comm);
	TRACEEVAL_SET_NUMBER(sched_keys[1], pid);

	TRACEEVAL_SET_DELTA(vals[0], val, record->ts);
	traceeval_insert(data->teval, sched_keys, vals);

	return 0;
}

static void show_latency(struct data *data)
{
	struct traceeval_iterator *iter = traceeval_iterator_get(data->teval);
	const struct traceeval_data *keys;

	printf("\n");
	while (traceeval_iterator_next(iter, &keys) > 0) {
		struct traceeval_stat *stat;
		unsigned long long val;
		unsigned long long ts;

		stat = traceeval_iterator_stat(iter, sched_vals[0].name);
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

	data.teval = traceeval_init(sched_keys, sched_vals);
	if (traceeval_delta_create(data.teval, delta_keys, NULL) < 0) {
		perror("Failed to create traceeval delta");
		exit(-1);
	}

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
