//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") write_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};


struct bpf_map_def SEC("maps") kprobe_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(u64),
        .max_entries = 1,
};


SEC("kprobe/sys_execve")
int kprobe_execve() {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	return 0;
}

SEC("kprobe/sys_write")
int kprobe__sys_write(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    int fd;
    #if defined(__aarch64__)
        bpf_probe_read(&fd, sizeof(fd), (void*)ctx->regs[0]);
    #elif defined(__x86_64__)
        bpf_probe_read(&fd, sizeof(fd), (void*)ctx->di);
    #else
        #error "Unsupported platform"
    #endif

    u64 zero = 0, *val;
    val = bpf_map_lookup_elem(&write_map, &pid);
    if (!val) {
        bpf_map_update_elem(&write_map, &pid, &zero, BPF_ANY);
        val = bpf_map_lookup_elem(&write_map, &pid);
        if (!val) {
            /* failed to insert pid into write_map */
            return 0;
        }
    }

    char msg[256];
    #if defined(__aarch64__)
        bpf_probe_read_user(&msg, sizeof(msg), (void *)ctx->regs[1]);
    #elif defined(__x86_64__)
        bpf_probe_read_user(&msg, sizeof(msg), (void *)ctx->si);
    #else
        #error "Unsupported platform"
    #endif

    bpf_trace_printk("pid %d write to fd %d\n", pid, fd);

    return 0;
}
