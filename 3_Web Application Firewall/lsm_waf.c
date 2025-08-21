#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 21
#define WEB_USER 33

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, sizeof(u32));
} allowed_bins SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm) {
    u32 cred_uid = -1;
    char current_comm[MAX_FILENAME_LEN] = { 0 };

    bpf_probe_read_kernel(&cred_uid, sizeof(cred_uid), &(bprm->cred->uid.val)); // 명령 실행한 UID 추출
    bpf_probe_read_kernel_str(current_comm, sizeof(current_comm), bprm->filename); // 명령 실행한 Filename 추출

    if (cred_uid == WEB_USER) { // 명령 실행한 UID가 Web Server 구동하는 유저와 동일한 경우
        bpf_printk("Current Command is: %s\n", current_comm);
        int *allowed = bpf_map_lookup_elem(&allowed_bins, &current_comm); // 사전에 허용된 명령인지 확인하고
        if (allowed == NULL) { // 허용되지 않은 명령인 경우
            bpf_printk("Block Command: %s\n", current_comm);
            return -1; // 명령 실행 차단.
        }
    }
    return 0;
}