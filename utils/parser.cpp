#include "parser.hpp"
#include <string>
#include <vector>

void Parser::extract_flags(std::string command) {
    int n = command.length();
    int start = -1;

    for(int i = 0; i < n; i++) {
        if(start != -1) this->flags.push_back(command[i]);
        else if(command[i] == '-') start = i;
        else if(command[i] == ' ' && start != -1) start = -1;
    }
}
