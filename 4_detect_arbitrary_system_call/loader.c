#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "loader.skel.h"
#include "datastr.h"

#define MAX_TIME_LEN 80

static int SetMemory() {
    struct rlimit newlimits = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &newlimits)) {
        fprintf(stderr, "Error in increasing memory for UserSpace App.\n");
        return 1;
    }
    return 0;
}

void getTime(char *timeBuf, long long unsigned int *nsec) {
    uint64_t seconds = (*nsec) / 1000000000ULL;
    uint16_t remain_seconds;
    uint16_t minutes = seconds / 60;
    uint64_t hours = minutes / 60;
    remain_seconds = seconds % 60;
    uint64_t nanosec = (*nsec) % 1000000000ULL;

    snprintf(timeBuf, MAX_TIME_LEN, "%lu:%02d:%02d, %luns", hours, minutes % 60, remain_seconds, nanosec);
}

static int handle_buf(void *ctx, void *data, size_t data_size) {
    struct syscall_data *element = data;
    char timeBuf[MAX_TIME_LEN];
    if (data_size < 0) {
        fprintf(stderr, "Incomplete data received.\n");
        return 1;
    }
    if (strncmp(element->comm, "loader.o", MAX_FILENAME_LEN)) {

        getTime(timeBuf, &(element->cur_nsec));

        printf("Uptime: %s\n", timeBuf);
        printf("Executed Command: %s\n", element->comm);
        printf("Syscall ID: %d\n", element->syscall_id);
        printf("PID: %d | PPID: %d | UID: %d\n", element->pid, element->ppid, element->uid);
        printf("-----------------------------------------\n");
    }
    return 0;
}

int main(void) {
    if (SetMemory()) {
        return 1;
    }

    struct ring_buffer *buf = NULL;
    struct loader *skel = NULL;
    int error = -1;
    
    skel = loader__open();
    loader__load(skel);
    loader__attach(skel);

    buf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_syscall), handle_buf, NULL, NULL);

    if (buf == NULL) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while(1) {
        error = ring_buffer__poll(buf, 100);
        if (error == -EINTR) {
            error = 0;
            break;
        }
        if (error < 0) {
            printf("Error Polling perf buffer: %d\n", error);
            break;
        }
        sleep(2);
    }

    return 0;
}