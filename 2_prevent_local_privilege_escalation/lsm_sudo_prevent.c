#include "vmlinux.h"
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 21

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, sizeof(u32));
} not_allowed_bins SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm) { // Macro BPF_PROG(Name, args...)
/*
    bprm_check_security -> Binary Code (Program) 실행 전 수행되는 LSM.
    실행되는 Binary Code 의 Filename, UID, EUID 읽고
    명령을 실행한 User 의 UID 및 실행 명령을 읽어서,

    명령 실행 User 가 Root 가 아니면 (UID != 0)
    Loader 를 통해 설정한 Not_ALlowed_Bins (MAP) 에서 Binary Code 의 Filename (Path) 를 찾는다.
    만약 MAP 에 해당 명령이 존재하는 경우, -1를 반환하고 (= 실행 차단), 그렇지 않으면 0 반환 (= 실행 허가)
*/

    u32 cred_uid = -1; // UserID - 사용자가 로그인한 계정의 ID
    u32 cred_eid = -1; // Effective UserID - 유효 사용자 ID (프로세스가 실행되는 주체의 UID)
    u32 user_uid = -1;
    // cf. 일반적으로, setuid() 명령을 사용하거나, setuid 비트가 설정되지 않는 한, UID 와 EUID 는 동일하다.

    char fname[MAX_FILENAME_LEN] = { 0 };

    bpf_probe_read_kernel_str(fname, sizeof(fname), bprm->filename); // Binary Code 실행한 Command
    // 마지막 character -> '\0' 덮어쓰기
    bpf_probe_read_kernel(&cred_uid, sizeof(cred_uid), &bprm->cred->uid.val); // Binary Code 실행한 UID
    bpf_probe_read_kernel(&cred_eid, sizeof(cred_eid), &bprm->cred->euid.val); // Binary Code 실행한 EUID
    bpf_probe_read_kernel(&user_uid, sizeof(user_uid), &(bprm->cred->user->uid.val)); // 실제 사용자의 UID (RUID)

    struct task_struct *task = bpf_get_current_task_btf(); // 실행될 프로그램(Binary Code)에 대한 정보 읽기
    char parent_comm[16]; // 명령을 실행한 User 가 실제로 입력한 Command 읽기
    bpf_probe_read_kernel(&parent_comm, sizeof(parent_comm), &task->real_parent->comm);

    u32 parent_uid = -1; // 명령 실행 User ID 읽기
    bpf_probe_read_kernel(&parent_uid, sizeof(parent_uid), &task->real_parent->cred->uid.val);

    bpf_printk("Parent command is %s with UID %d \n", parent_comm, parent_uid); 
    // 로그인된 유저가 실행한 명령 및 해당 유저의 UID 

    bpf_printk("Filename using read_kernel: %s with UID %d and EID %d and UserID %d\n", fname, cred_uid, cred_eid, user_uid);
    // Binary Code 실행한 UID, EUID, RUID
    if (parent_uid == 0) { // Root User 인 경우
        return 0;
    }

    int *notallowed = bpf_map_lookup_elem(&not_allowed_bins, &fname); 
    // not Root User 인 경우, 실행한 명령이 Not Allowed List (MAP) 에 존재하는지 확인.
    if (notallowed) { // 존재한다면 (=실행 금지 명령을 실행한 경우)
        if (cred_uid == 0) { // 해당 명령이 Root 권한으로 실행된 경우에는
            bpf_printk("sudo attempted for %s: UID :%d \n", fname);
            return -1; // 프로그램 실행을 차단함.
        }
    }

    return 0;
}