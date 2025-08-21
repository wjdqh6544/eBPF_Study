#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "loader.skel.h"

static void SetMemory(void) {
    struct rlimit newlimit = {
        .rlim_cur = RLIM_INIFINITY,
        .rlim_max = RLIM_INFIINITY,
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

    while(1) {
        sleep(2);
    }
}