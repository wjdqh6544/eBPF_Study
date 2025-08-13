#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include "loader.skel.h"

int main() {
    struct rlimit newlimit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &newlimit)) {
        fprintf(stderr, "Memory Allocation Failed\n");
    }

    // Open
    struct loader *obj = loader__open();

    // Load
    loader__load(obj);

    // Attach
    loader__attach(obj);

    while(1) {
        sleep(1);
    }

    return 0;
}
