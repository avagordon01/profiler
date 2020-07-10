#!/usr/bin/env python
import bcc
import stacks
from collections import namedtuple

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

tick_t = namedtuple('tick', ['tick', 'tid', 'time'])
ticks = []
sample_t = namedtuple('sample', ['stack', 'tick', 'tid'])
stack_counts = {}
def report(b):
    samples = b["samples"]
    traces = b["output_traces"]
    stack_traces = b["stack_traces"]
    for k, v in samples.items():
        try:
            stack, count = stacks.format_stack(b, k, v, stack_traces)
            key = sample_t(stack, k.tick, k.tid)
            if key in stack_counts:
                stack_counts[key] += count
            else:
                stack_counts[key] = count
        except KeyError:
            pass
    for k, v in traces.items():
        ticks.append(tick_t(k.tick, k.tid, v.value))
    samples.clear()
    traces.clear()

    ticks.sort(key=lambda x: (x.tid, x.tick))
    tick_times = []
    for tick0, tick1 in zip(ticks[:-1], ticks[1:]):
        if tick0.tid == tick1.tid and tick0.tick + 1 == tick1.tick:
            tick_times.append(tick_t(tick0.tick, tick0.tid, tick1.time - tick0.time))
    tick_times.sort(key=lambda x: (x.time))
    split = int(len(tick_times) * 0.95)
    good_ticks = set([(t.tick, t.tid) for t in tick_times[:split]])
    bad_ticks = set([(t.tick, t.tid) for t in tick_times[split:]])

    good_samples = {}
    for k, v in stack_counts.items():
        if (k.tick, k.tid) in good_ticks:
            if k.stack in good_samples:
                good_samples[k.stack] += v
            else:
                good_samples[k.stack] = v
    bad_samples = {}
    for k, v in stack_counts.items():
        if (k.tick, k.tid) in bad_ticks:
            if k.stack in bad_samples:
                bad_samples[k.stack] += v
            else:
                bad_samples[k.stack] = v

    with open('bad-stacks', 'w') as f:
        f.write(''.join(['{} {}\n'.format(k, v) for k, v in bad_samples.items()]))

    with open('good-stacks', 'w') as f:
        f.write(''.join(['{} {}\n'.format(k, v) for k, v in bad_samples.items()]))

    print('ticks    goods {} bads {}'.format(len(good_ticks), len(bad_ticks)))
    print('samples  goods {} bads {}'.format(len(good_samples), len(bad_samples)))
