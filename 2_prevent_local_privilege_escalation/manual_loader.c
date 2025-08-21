#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "loader.skel.h"

#define MAX_FILENAME_LEN 21

static void SetMemory() {
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
    printf("App Loaded\n");
    int map_notallowed_fd = bpf_map__fd(skel->maps.not_allowed_bins);
    printf("Map FD: %d\n", map_notallowed_fd);

    if (map_notallowed_fd < 0) {
        fprintf(stderr, "ERROR: finding not_allowed map in skeleton object file Failed\n");
        return 1;
    }

    int not_allowed = 1;

    const char *not_allowed_bins[] = { "/usr/bin/python", "/usr/bin/find", "/usr/bin/perl", "/usr/bin/python3" };
    for (int i = 0; i < 4; i++) {
        char key[MAX_FILENAME_LEN] = { 0 };
        strncpy(key, not_allowed_bins[i], MAX_FILENAME_LEN - 1);
        key[MAX_FILENAME_LEN - 1] = '\0';
        printf("%s\n", key);
        printf("key[12 -]: %02x %02x %02x %02x %02x %02x %02x %02x \n", key[12], key[13], key[14], key[15], key[16], key[17], key[18], key[19]);
        
        int ret = bpf_map_update_elem(map_notallowed_fd, key, &not_allowed, BPF_ANY);
        if (ret != 0) {
            fprintf(stderr, "ERROR: adding to not_allowed_list failed\n");
            return 1;
        }
    }
    printf("Hook Placed. Press enter to exit.\n");
    getchar();

    return 0;
}