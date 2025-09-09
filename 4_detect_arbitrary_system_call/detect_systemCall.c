#include "datastr.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);    // int (*name)[val]; RingBuffer // 원형 큐
    __uint(max_entries, 1 << 20); // 1MB (2^20)
} ringbuf_syscall SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int bpf_trace_syscall_entry(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *task;
    struct syscall_data *calldata;
    struct timespec64 ts;

    calldata = bpf_ringbuf_reserve(&ringbuf_syscall, sizeof(struct syscall_data), 0); // Reserve Buffer
    if (calldata == NULL) {
        return 0;
    }

    bpf_get_current_comm(&(calldata->comm), sizeof(calldata->comm));

    task = bpf_get_current_task_btf(); // Process Info

    calldata->syscall_id = ctx->args[1];
    calldata->pid = bpf_get_current_pid_tgid() >> 32;
    calldata->ppid = task->real_parent->tgid;
    calldata->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    calldata->cur_nsec = bpf_ktime_get_ns();

    bpf_printk("ID - %d, test: %d\n", ctx->args[1], ctx->args[2]);

    bpf_ringbuf_submit(calldata, 0);

    return 0;
}