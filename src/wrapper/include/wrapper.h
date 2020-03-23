#include "log.h"
#include <string>

class Wrapper {
private:
    char** argv;
    std::string argv2Str();
public:
    Wrapper(char** arg) : argv(arg) {}
    ~Wrapper() {}
    int instrumentation();
};
