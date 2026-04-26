#include "helpers.hpp"
#include <cstdlib>
#include <iostream>
#include <string>

Helpers::Helpers() = default;

std::string Helpers::get_runtime() {
    int podman = std::system("podman --version > /dev/null 2>&1");
    if (podman == 0) {
        std::cout<<"Podman Runtime Detected...";
        return "podman";
    }

    int docker = std::system("docker --version > /dev/null 2>&1");
    if (docker == 0) {
        std::cout<<"Docker Runtime Detected...";
        return "docker";
    }

    return "";
}
