#include "wrapper.h"
#include <iostream>
#include <cstdlib>

using std::string;

const char* fname = "wrapper.cpp";

extern void log_msg(LOG_LEVEL, const char*, const char*);

string Wrapper::argv2Str() {
    char** tmp = this->argv;
    *tmp++;
    string str("");
    while(*tmp) {
        str.append(*tmp++);
        str.append(" ");
    }
    return str;
}

int Wrapper::instrumentation() {
    string env = "export LD_PRELOAD=/root/project/SFuzzer/build/bin/libhook.so:$LD_PRELOAD && ";
    string cmd = env + this->argv2Str();
    log_msg(SF_INFO, fname, cmd.c_str());

    system(cmd.c_str());
    
    return 0;
}
