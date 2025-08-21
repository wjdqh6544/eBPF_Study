#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "loader.skel.h"

#define MAX_FILENAME_LEN 21
#define COMM_LEN 16

static void SetMemory(void) {
    struct rlimit newlimit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &newlimit)) {
        fprintf(stderr, "Error in increasing memory for UserSpace App!\n");
    }
}

int main(void) {
    SetMemory();

    struct loader *skel = loader__open();
    loader__load(skel);
    loader__attach(skel);
    printf("eBPF/LSM WAF Hook loaded\n");

    int map_allowed_bin_fd = bpf_map__fd(skel->maps.allowed_bins);
    printf("Map FD: %d\n", map_allowed_bin_fd);
    if (map_allowed_bin_fd < 0) {
        fprintf(stderr, "ERROR: Finding allowed map in skeleton object file failed.\n");
        return 1;
    }

    int allowed = 1;
    const char *allowed_fnames[] = { "/usr/bin/ping", "/bin/sh" };

    for (int i = 0; i < 2; i++) {
        char key[MAX_FILENAME_LEN] = { 0 };
        strncpy(key, allowed_fnames[i], MAX_FILENAME_LEN - 1);
        key[MAX_FILENAME_LEN - 1] = '\0';
        printf("%s\n", key);

        int ret = bpf_map_update_elem(map_allowed_bin_fd, key, &allowed, BPF_ANY);
        if (ret != 0) {
            fprintf(stderr, "ERROR: Adding to allowed list failed\n"); 
            return 1;
        }
    }

    printf("WAF Hook in action. Press enter to exit.\n");
    getchar();
    return 0;
}