#include "image.hpp"

#include <utility>

Image::Image(std::string format, int height, int width, std::vector<int> buffer)
    : format(std::move(format)), height(height), width(width), buffer(std::move(buffer)) {}
