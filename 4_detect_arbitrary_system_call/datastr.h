#define COMM_LEN 16
#define MAX_FILENAME_LEN 21

typedef unsigned int __u32;

struct syscall_data {
    __u32 syscall_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    long long unsigned int cur_nsec;
    char comm[COMM_LEN];
};