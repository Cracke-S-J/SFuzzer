#include "wrapper.h"

int main(int argc, char* argv[]) {
    Wrapper wrapper(argv);
    wrapper.instrumentation();

    return 0;
}
