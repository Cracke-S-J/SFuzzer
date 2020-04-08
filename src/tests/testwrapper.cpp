#include "wrapper.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "usage\n";
        return 0;
    }
    Wrapper wrapper(argv);
    wrapper.instrumentation();

    return 0;
}
