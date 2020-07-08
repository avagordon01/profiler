#!/usr/bin/env python
import bcc
import stacks

def compile(addresses):
    bpf_text = """
    #include <uapi/linux/bpf_perf_event.h>
    #include <linux/sched.h> //TASK_COMM_LEN

    typedef u32 tid_t;
    typedef u64 tick_t;
    typedef u64 time_t;

    BPF_HASH(current_ticks, tid_t, tick_t);

    struct output_trace {
        tick_t tick;
        tid_t tid;
    };
    BPF_HASH(output_traces, struct output_trace, time_t);

    struct sample {
        tick_t tick;
        tid_t tid;
        int user_stack_id;
        char command[TASK_COMM_LEN];
    };
    BPF_HASH(samples, struct sample, u32);

    BPF_STACK_TRACE(stack_traces, 4096);

    int on_trace(struct pt_regs *ctx) {
        tid_t tid = bpf_get_current_pid_tgid();
        tick_t tick;
        if (true) {
            const void* address = (const void*)ctx->r13;
            address += """ + str(addresses[0]) + """;
            if (bpf_probe_read_user(&tick, sizeof(tick), address) != 0) {
                //couldn't read the variable in this trace
                return 0;
            }
            current_ticks.update(&tid, &tick);
        } else {
            tick_t zero = 0;
            tick_t* tp = current_ticks.lookup_or_try_init(&tid, &zero);
            if (tp) {
                current_ticks.increment(tid);
                tick = *tp;
            } else {
                tick = 0;
            }
        }
        struct output_trace output = {};
        output.tick = tick;
        output.tid = tid;
        time_t current_time = bpf_ktime_get_ns();
        output_traces.insert(&output, &current_time);
        return 0;
    }

    int on_sample(struct bpf_perf_event_data *ctx) {
        tid_t tid = bpf_get_current_pid_tgid();
        tick_t* tp = current_ticks.lookup(&tid);
        if (!tp) {
            //ignore sample, not from a tid with a previous trace
            return 0;
        }
        struct sample s = {};
        s.tick = *tp;
        s.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
        s.tid = tid;
        bpf_get_current_comm(&s.command, sizeof(s.command));
        samples.increment(s);
        return 0;
    }
    """

    b = bcc.BPF(text=bpf_text)
    return b

def attach(b, binary, offset):
    b.attach_uprobe(
        name=binary,
        addr=offset,
        fn_name="on_trace"
    )

    b.attach_perf_event(
        ev_type=bcc.PerfType.SOFTWARE,
        ev_config=bcc.PerfSWConfig.CPU_CLOCK,
        fn_name="on_sample",
        sample_period=0,
        sample_freq=4096,
        cpu=-1
    )

stack_counts = {}
tick_times = []
def report(b):
    samples = b["samples"]
    traces = b["output_traces"]
    stack_traces = b["stack_traces"]
    for k, v in samples.items():
        print("tick {} tid {}".format(k.tick, k.tid))
        try:
            stack, count = stacks.format_stack(b, k, v, stack_traces)
            if stack in stack_counts:
                stack_counts[stack] += count
            else:
                stack_counts[stack] = count
        except KeyError:
            pass
    traces_sorted = sorted(traces.items(), key=lambda kv: kv[1].value)
    #print(['tick {} tid {} time {:,}'.format(x[0].tick, x[0].tid, x[1].value)
        #for x in traces_sorted if x[1].value > 1e9])
    tick_times.extend([{'tick': k.tick, 'tid': k.tid, 'time': v.value} for k, v in traces.items()])
    tick_times.sort(key=lambda x: x['time'])
    try:
        #print('tick {} tid {} time {:,}'.format(tick_times[0]['tick'], tick_times[0]['tid'], tick_times[0]['time']))
        #print('tick {} tid {} time {:,}'.format(tick_times[-1]['tick'], tick_times[-1]['tid'], tick_times[-1]['time']))
        pass
    except IndexError:
        pass
    samples.clear()
    traces.clear()
