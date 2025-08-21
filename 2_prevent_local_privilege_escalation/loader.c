#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "loader.skel.h"

static int setMemoryForUserSpace(void) {
    struct rlimit newlimit {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &newlimit)) {
        fprintf(stderr, "Error in increasing memory for userSpace app! \n");
        return 1;
    }

    return 0;
}

int main(void) {
    setMemoryForUserSpace();

    struct loadert *skel = loader__open();
    loader__load(skel);
    loader__attach(skel);

    while(1) {
        sleep(2);
    }

    return 0;
}