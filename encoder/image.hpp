#pragma once

#include <string>
#include <vector>

class Image {
public:
    std::string format;
    int height;
    int width;
    std::vector<int> buffer;

    Image(std::string format, int height, int width, std::vector<int> buffer);
};
